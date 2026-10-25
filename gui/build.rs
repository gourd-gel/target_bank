// Compiles ui/app.slint into Rust code at build time.
//
// The "fluent-light" style is forced so the ATM looks the same in macOS
// light and dark mode (an ATM screen should not follow the OS theme).
fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-light".into());
    slint_build::compile_with_config("ui/app.slint", config).expect("Slint UI failed to compile");
}
