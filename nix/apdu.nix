{
  lib,
  buildGoModule,
}:
buildGoModule {
  pname = "apdu";
  version = "0.3.0";

  src = lib.cleanSource ./..;

  vendorHash = null;

  doCheck = true;

  meta = with lib; {
    description = "Go APDU encoding and decoding library";
    homepage = "https://github.com/skythen/apdu";
    license = licenses.mit;
  };
}