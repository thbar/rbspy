pub use self::os_impl::*;
use libc::pid_t;

/*
 * Operating-system specific code for getting
 * a) the address of the current thread, and
 * b) the address of the Ruby version of a PID
 *
 * from a running Ruby process. Involves a lot of reading memory maps and symbols.
 */

#[derive(Fail, Debug)]
pub enum AddressFinderError {
    #[fail(display = "No process with PID: {}", _0)] NoSuchProcess(pid_t),
    #[fail(display = "Permission denied when reading from process {}. Try again with sudo?", _0)]
    PermissionDenied(pid_t),
    #[fail(display = "Error reading /proc/{}/maps", _0)] ProcMapsError(pid_t),
}

#[cfg(target_os = "macos")]
mod os_impl {
    use goblin::mach;
    use failure::Error;
    use failure::ResultExt;
    use std;
    use std::io::Read;
    use std::sync::Mutex;
    use std::sync::Arc;
    use std::process::{Command, Stdio};
    use libc::pid_t;
    use proc_maps::MapRange;
    use read_process_memory::*;
    use mac_maps::{MacMapRange, get_process_maps, task_for_pid};

    pub fn get_ruby_version_address(pid: pid_t) -> Result<usize, Error> {
        let proginfo: ProgramInfo = get_program_info(pid, true)?;
        proginfo.get_symbol("_ruby_version")
    }

    pub fn current_thread_address(
        pid: pid_t,
        version: &str,
        _is_maybe_thread: Box<Fn(usize, &ProcessHandle, &Vec<MapRange>) -> bool>,
    ) -> Result<usize, Error> {
        // TODO: Make this actually look up the `__mh_execute_header` base
        //  address in the binary via `nm`.
        let proginfo = &get_program_info(pid, false)?;
        if version >= "2.5.0" {
            proginfo.get_symbol("_ruby_current_execution_context_ptr")
        } else {
            debug!("getting symbol");
            proginfo.get_symbol("_ruby_current_thread")
        }
    }

    struct Addr {
        pub start_addr: usize,
        pub mach: Vec<u8>,
    }

    impl ProgramInfo {
        pub fn get_symbol(&self, symbol_name: &str) -> Result<usize, Error> {
            if let Some(x) = self.ruby_addr.get_symbol(symbol_name)? {
                Ok(x)
            } else if let Some(y) = self.libruby_addr.as_ref() {
                match y.get_symbol(symbol_name)? {
                    Some(sym) => Ok(sym),
                    None => Err(format_err!("Couldn't find symbol")),
                }
            } else {
                Err(format_err!("Couldn't find right Ruby mach file"))
            }
        }
    }

    impl Addr {
        pub fn from(start_addr: usize, filename: &str) -> Result<Addr, Error> {
            let mut file = std::fs::File::open(&filename)?;
            let mut contents: Vec<u8> = Vec::new();
            file.read_to_end(&mut contents)?;
            Ok(Addr{start_addr: start_addr, mach: contents})
        }

        pub fn get_symbol(&self, symbol_name: &str) -> Result<Option<usize>, Error> {
            let mach = match mach::Mach::parse(&self.mach) {
                Ok(mach::Mach::Binary(m)) => m,
                Ok(mach::Mach::Fat(m)) => m.get(0).unwrap(),
                _ => {return Err(format_err!("Couldn't parse Mach-O binary"));},
            };
            let base_address: usize = if symbol_name == "_ruby_version" {
                0x100000000
            } else {
                0x100000000
            };
            let base_address = 0;
            match mach.symbols.as_ref() {
                Some(symbols) => {
                    for x in symbols.iter() {
                        let (name, sym) = x.unwrap();
                        if name == symbol_name {
                            return Ok(Some(sym.n_value as usize + self.start_addr - base_address));
                        }
                    }
                    Ok(None)
                }
                None => Ok(None),
            }
        }
    }

    struct ProgramInfo {
        pub pid: pid_t,
        pub ruby_addr: Addr,
        pub libruby_addr: Option<Addr>,
    }

    fn get_program_info(pid: pid_t, reload: bool) -> Result<ProgramInfo, Error> {
        let task = task_for_pid(pid).context(format!("Couldn't get port for PID {}", pid))?;
        let vmmap = get_process_maps(pid, task);
        Ok(ProgramInfo{
            pid: pid,
            ruby_addr: get_maps_address(&vmmap)?,
            libruby_addr: get_libruby_address(&vmmap)?,
        })
    }

    fn cache_vmmap_output(pid: pid_t, reload: bool) -> Result<String, Error> {
        lazy_static! {
            static ref CACHE: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        }
        let mut state = CACHE.lock().unwrap();
        // only return a cached value if reload = false
        if !reload {
            if let Some(ref x) = *state {
                return Ok(x.clone());
            }
        }
        let output = get_vmmap_output(pid)?;
        std::mem::replace(&mut *state, Some(output.clone()));
        Ok(output)
    }

    fn get_vmmap_output(pid: pid_t) -> Result<String, Error> {
        let vmmap_command = Command::new("vmmap")
            .arg(format!("{}", pid))
            .stdout(Stdio::piped())
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        if !vmmap_command.status.success() {
            panic!(
                "failed to execute process: {}",
                String::from_utf8(vmmap_command.stderr).unwrap()
                )
        }

        Ok(String::from_utf8(vmmap_command.stdout)?)
    }


    fn get_libruby_address(maps:&Vec<MacMapRange>) -> Result<Option<Addr>, Error> {
        Ok(None)
    }

    fn get_maps_address(maps: &Vec<MacMapRange>) -> Result<Addr, Error> {
        let map: &MacMapRange = maps.iter()
            .find(|ref m| {
                println!("{:?}", m);
                if let Some(ref pathname) = m.filename {
                    pathname.contains("bin/ruby") && m.is_exec()
                } else {
                    false
                }
            }).ok_or(format_err!("Couldn't find ruby map"))?;
        println!("{:?}", map);
        Addr::from(map.start as usize, map.filename.as_ref().unwrap())
    }
}

#[cfg(target_os = "linux")]
mod os_impl {
    use copy::*;
    use elf;
    use proc_maps::*;
    use failure::Error;
    use libc::pid_t;
    use std;
    use address_finder::AddressFinderError;
    use read_process_memory::*;

    pub fn current_thread_address(
        pid: pid_t,
        version: &str,
        is_maybe_thread: Box<Fn(usize, &ProcessHandle, &Vec<MapRange>) -> bool>,
    ) -> Result<usize, Error> {
        let proginfo = &get_program_info(pid)?;
        match current_thread_address_symbol_table(proginfo, version) {
            Some(addr) => Ok(addr),
            None => {
                debug!("Trying to find address location another way");
                Ok(current_thread_address_search_bss(
                    proginfo,
                    is_maybe_thread,
                )?)
            }
        }
    }

    pub fn get_ruby_version_address(pid: pid_t) -> Result<usize, Error> {
        let proginfo = &get_program_info(pid)?;
        let symbol_addr = get_symbol_addr(&proginfo.ruby_map, &proginfo.ruby_elf, ruby_version_symbol);
        match symbol_addr {
            Some(addr) => Ok(addr),
            _ => {
                get_symbol_addr(
                    // if we have a ruby map but `ruby_version` isn't in it, we expect there to be
                    // a libruby map. If that's not true, that's a bug.
                    (*proginfo.libruby_map)
                        .as_ref()
                        .ok_or(format_err!("Missing libruby map. Please report this!"))?,
                    proginfo
                        .libruby_elf
                        .as_ref()
                        .ok_or(format_err!("Missing libruby ELF. Please report this!"))?,
                    ruby_version_symbol,
                ).ok_or(format_err!("Couldn't find ruby version."))
            }
        }
    }

    fn elf_symbol_value(elf_file: &elf::File, symbol_name: &str) -> Option<usize> {
        // TODO: maybe move this to goblin so that it works on OS X & BSD, not just linux
        let sections = &elf_file.sections;
        for s in sections {
            for sym in elf_file
                .get_symbols(&s)
                .expect("Failed to get symbols from section")
            {
                debug!("sym name: {}", sym.name);
                if sym.name == symbol_name {
                    debug!("symbol: {}", sym);
                    return Some(sym.value as usize);
                }
            }
        }
        None
    }

    fn get_bss_section(elf_file: &elf::File) -> Option<elf::types::SectionHeader> {
        for s in &elf_file.sections {
            match s.shdr.name.as_ref() {
                ".bss" => {
                    return Some(s.shdr.clone());
                }
                _ => {}
            }
        }
        None
    }

    fn current_thread_address_search_bss(
        proginfo: &ProgramInfo,
        is_maybe_thread: Box<Fn(usize, &ProcessHandle, &Vec<MapRange>) -> bool>,
    ) -> Result<usize, Error> {
        // Used when there's no symbol table. Looks through the .bss and uses a search_bss (found in
        // `is_maybe_thread`) to find the address of the current thread.
        let map = (*proginfo.libruby_map).as_ref().expect(
            "No libruby map: symbols are stripped so we expected to have one. Please report this!",
        );
        let libruby_elf = proginfo.libruby_elf.as_ref().expect(
            "No libruby elf: symbols are stripped so we expected to have one. Please report this!",
        );
        let bss_section = get_bss_section(libruby_elf).expect(
            "No BSS section (every Ruby ELF file should have a BSS section?). Please report this!",
        );
        let load_header = elf_load_header(libruby_elf);
        debug!("bss_section header: {:?}", bss_section);
        let read_addr = map.range_start + bss_section.addr as usize - load_header.vaddr as usize;

        debug!("read_addr: {:x}", read_addr);
        let source = &proginfo.pid.try_into_process_handle().unwrap();
        let mut data = copy_address_raw(read_addr as usize, bss_section.size as usize, source)?;
        debug!("successfully read data");
        let slice: &[usize] = unsafe {
            std::slice::from_raw_parts(
                data.as_mut_ptr() as *mut usize,
                data.capacity() as usize / std::mem::size_of::<usize>() as usize,
            )
        };

        let i = slice
            .iter()
            .position({ |&x| is_maybe_thread(x, source, &proginfo.all_maps) })
            .ok_or(format_err!(
                "Current thread address not found in process {}",
                &proginfo.pid
            ))?;
        Ok((i as usize) * (std::mem::size_of::<usize>() as usize) + read_addr)
    }

    fn current_thread_address_symbol_table(
        // Uses the symbol table to get the address of the current thread
        proginfo: &ProgramInfo,
        version: &str,
    ) -> Option<usize> {
        // TODO: comment this somewhere
        if version >= "2.5.0" {
            // TODO: make this more robust
            get_symbol_addr(
                &proginfo.ruby_map,
                &proginfo.ruby_elf,
                "ruby_current_execution_context_ptr",
            )
        } else {
            get_symbol_addr(
                &proginfo.ruby_map,
                &proginfo.ruby_elf,
                "ruby_current_thread",
            )
        }
    }

    fn get_symbol_addr(map: &MapRange, elf_file: &elf::File, symbol_name: &str) -> Option<usize> {
        elf_symbol_value(elf_file, symbol_name).map(|addr| {
            let load_header = elf_load_header(elf_file);
            debug!("load header: {}", load_header);
            map.range_start + addr - load_header.vaddr as usize
        })
    }

    fn elf_load_header(elf_file: &elf::File) -> elf::types::ProgramHeader {
        elf_file
            .phdrs
            .iter()
            .find(|ref ph| {
                ph.progtype == elf::types::PT_LOAD && (ph.flags.0 & elf::types::PF_X.0) != 0
            })
            .expect("No executable LOAD header found in ELF file. Please report this!")
            .clone()
    }

    // struct to hold everything we know about the program
    pub struct ProgramInfo {
        pub pid: pid_t,
        pub all_maps: Vec<MapRange>,
        pub ruby_map: Box<MapRange>,
        pub libruby_map: Box<Option<MapRange>>,
        pub ruby_elf: elf::File,
        pub libruby_elf: Option<elf::File>,
    }

    pub fn get_program_info(pid: pid_t) -> Result<ProgramInfo, Error> {
        let all_maps = get_proc_maps(pid).map_err(|x| match x.kind() {
            std::io::ErrorKind::NotFound => AddressFinderError::NoSuchProcess(pid),
            std::io::ErrorKind::PermissionDenied => AddressFinderError::PermissionDenied(pid),
            _ => AddressFinderError::ProcMapsError(pid),
        })?;
        let ruby_map = Box::new(get_map(&all_maps, "bin/ruby", "r-xp")
            .ok_or(format_err!("Ruby map not found for PID: {}", pid))?);
        let ruby_path = &ruby_map
            .pathname
            .clone()
            .expect("ruby map's pathname shouldn't be None");
        let ruby_elf = elf::File::open_path(ruby_path)
            .map_err(|_| format_err!("Couldn't open ELF file: {}", ruby_path))?;
        let all_maps = get_proc_maps(pid).unwrap();
        let libruby_map = Box::new(get_map(&all_maps, "libruby", "r-xp"));
        let libruby_elf = match *libruby_map {
            Some(ref map) => {
                let path = &map.pathname
                    .clone()
                    .expect("libruby map's pathname shouldn't be None");
                Some(elf::File::open_path(path)
                    .map_err(|_| format_err!("Couldn't open ELF file: {}", path))?)
            }
            _ => None,
        };
        Ok(ProgramInfo {
            pid: pid,
            all_maps: all_maps,
            ruby_map: ruby_map,
            libruby_map: libruby_map,
            ruby_elf: ruby_elf,
            libruby_elf: libruby_elf,
        })
    }

    fn get_map(maps: &Vec<MapRange>, contains: &str, flags: &str) -> Option<MapRange> {
        maps.iter()
            .find(|ref m| {
                if let Some(ref pathname) = m.pathname {
                    pathname.contains(contains) && &m.flags == flags
                } else {
                    false
                }
            })
            .map(|x| x.clone())
    }
}
