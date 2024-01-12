{ pkgs ? import <nixpkgs> {} }:

let
  rust-toolchain = with pkgs; symlinkJoin {
    name = "rust-toolchain";
    paths = [rustc cargo rustPlatform.rustcSrc];
  };
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    cargo-watch

    # For IntelliJ
    # Set intellij to this /bin location
    rust-toolchain
  ];
  # Env variable for IntelliJ. 
  # Set IntelliJ rust stdlib src to this path (env | grep RUST_SRC_PATH)
  RUST_SRC_PATH="${pkgs.rustPlatform.rustLibSrc}";
  RUST_BACKTRACE=1;
}

