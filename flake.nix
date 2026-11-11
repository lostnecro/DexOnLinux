{
  description = "Real Samsung DeX over USB on Linux";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      runtimeTools = pkgs: [
        pkgs.scrcpy
        pkgs.android-tools
      ];
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.stdenv.mkDerivation {
          pname = "dex-on-linux";
          version = "0.2.0";
          src = ./.;

          nativeBuildInputs = [
            pkgs.makeWrapper
          ];
          buildInputs = [
            pkgs.python3
            pkgs.openssl
          ];

          dontBuild = true;
          installPhase = ''
            runHook preInstall
            install -Dm755 dex_on_linux.py $out/bin/dex-on-linux
            wrapProgram $out/bin/dex-on-linux \
              --prefix PATH : ${pkgs.lib.makeBinPath (runtimeTools pkgs)} \
              --prefix LD_LIBRARY_PATH : ${pkgs.lib.makeLibraryPath [ pkgs.openssl ]}
            runHook postInstall
          '';

          meta.mainProgram = "dex-on-linux";
        };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = pkgs.lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.python3
            pkgs.openssl
          ] ++ runtimeTools pkgs;
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.openssl ];
        };
      });
    };
}
