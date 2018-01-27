Notes taken while working on https://github.com/rbspy/rbspy/issues/70

### How to list all tests

I think there was a technique for that in the past (e.g. `cargo list test`) but couldn't find it anymore, so I use this instead:

```
ag "fn (?=test_)" --no-filename --no-color | awk '{$1=$1};1' | sed '/^\s*$/d'
```

The output is:

```
fn test_parse_maps() {
fn test_get_nonexistent_process() {
fn test_get_disallowed_process() {
fn test_current_thread_address() {
fn test_write_flamegraph() {
fn test_output_filename() {
fn test_arg_parsing() {
fn test_get_ruby_stack_trace_2_1_6() {
fn test_get_ruby_stack_trace_1_9_3() {
fn test_get_ruby_stack_trace_2_5_0() {
fn test_get_ruby_stack_trace_2_4_0() {
```

### How to run a specific test with println! statements working

By default STDOUT is captured and not printed for successful tests.

To get the output one can use:

```
cargo run test_my_test -- --nocapture
```