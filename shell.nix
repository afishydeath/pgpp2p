{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  packages = with pkgs; [
    (python3.withPackages (
      p: with p; [
        pgpy
        tkinter
      ]
    ))
  ];
}
