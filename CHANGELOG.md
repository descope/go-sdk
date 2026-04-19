# Changelog

## [1.16.0](https://github.com/descope/go-sdk/compare/v1.15.0...v1.16.0) (2026-04-19)


### Features

* **fga:** add CheckWithContext for ABAC/CEL evaluation ([#729](https://github.com/descope/go-sdk/issues/729)) ([55ccf7c](https://github.com/descope/go-sdk/commit/55ccf7c32f2071f96e7ab4ea08d34159511025fa))
* **sso:** add WS-Fed SSO application management ([#727](https://github.com/descope/go-sdk/issues/727)) ([4544ea8](https://github.com/descope/go-sdk/commit/4544ea81bae18132bd8de48bd68bde3784904022))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.15.0 ([#725](https://github.com/descope/go-sdk/issues/725)) ([b64cdd1](https://github.com/descope/go-sdk/commit/b64cdd1197b7546e964256cb5e054a821c444646))

## [1.15.0](https://github.com/descope/go-sdk/compare/v1.14.0...v1.15.0) (2026-04-04)


### Features

* **user:** support userId in Invite and InviteBatch ([#713](https://github.com/descope/go-sdk/issues/713)) ([27fe5bc](https://github.com/descope/go-sdk/commit/27fe5bc712cd58ee7bbfafeea6f805f3839deb52))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.14.0 ([#718](https://github.com/descope/go-sdk/issues/718)) ([9c0a3e3](https://github.com/descope/go-sdk/commit/9c0a3e3762198bca53cc16d66ca72b901d44e0ed))

## [1.14.0](https://github.com/descope/go-sdk/compare/v1.13.0...v1.14.0) (2026-03-22)


### Features

* **http:** retry requests on transient error status codes ([#717](https://github.com/descope/go-sdk/issues/717)) ([71677c7](https://github.com/descope/go-sdk/commit/71677c72da6d64e1cfc4349d92ec1bd749f1dc94))
* **sso-app:** add default signature method ([#712](https://github.com/descope/go-sdk/issues/712)) ([9e27984](https://github.com/descope/go-sdk/commit/9e279846d1f34ea40c066d405ac3db7862e16721))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.13.0 ([#709](https://github.com/descope/go-sdk/issues/709)) ([9ff4a2d](https://github.com/descope/go-sdk/commit/9ff4a2db6fb1542af1bf813d4c67e8012ba247c9))

## [1.13.0](https://github.com/descope/go-sdk/compare/v1.12.0...v1.13.0) (2026-03-12)


### Features

* add lists exclude option in project import ([#706](https://github.com/descope/go-sdk/issues/706)) ([817111f](https://github.com/descope/go-sdk/commit/817111fb1cd2bd6c54a182d9b5f84d4833a58531))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.12.0 ([#704](https://github.com/descope/go-sdk/issues/704)) ([d5a5777](https://github.com/descope/go-sdk/commit/d5a5777fa461e85d7bbb9e9945942546b57f162f))

## [1.12.0](https://github.com/descope/go-sdk/compare/v1.11.0...v1.12.0) (2026-03-10)


### Features

* support additional logind ids on user patch request ([#703](https://github.com/descope/go-sdk/issues/703)) ([12cc236](https://github.com/descope/go-sdk/commit/12cc236f673efaae18008ff2b1bb592f104b43a7))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.11.0 ([#699](https://github.com/descope/go-sdk/issues/699)) ([396305a](https://github.com/descope/go-sdk/commit/396305afb28c9251715bcb8f646fc6eb4bfec76d))

## [1.11.0](https://github.com/descope/go-sdk/compare/v1.10.0...v1.11.0) (2026-02-26)


### Features

* **lists:** text crud ([a795d7d](https://github.com/descope/go-sdk/commit/a795d7df7e326c676a53682d0488b2038380e41a))
* **lists:** text crud ([a795d7d](https://github.com/descope/go-sdk/commit/a795d7df7e326c676a53682d0488b2038380e41a))
* refresh session with a writer and a given token ([#698](https://github.com/descope/go-sdk/issues/698)) ([a28b400](https://github.com/descope/go-sdk/commit/a28b400229aa0c680a2089b6d39cf34dd13e57e0))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.10.0 ([#695](https://github.com/descope/go-sdk/issues/695)) ([4534208](https://github.com/descope/go-sdk/commit/4534208cbeb61c33362c6d8fe5ac2e7bae94066f))

## [1.10.0](https://github.com/descope/go-sdk/compare/v1.9.0...v1.10.0) (2026-02-25)


### Features

* **authz:** route WhoCanAccess and WhatCanTargetAccess through FGA cache ([#689](https://github.com/descope/go-sdk/issues/689)) ([f6a1dc1](https://github.com/descope/go-sdk/commit/f6a1dc110109b09da9df4d53b9f31923fdda04c5))
* **lists:** add crud support ([#693](https://github.com/descope/go-sdk/issues/693)) ([1034c32](https://github.com/descope/go-sdk/commit/1034c327b613a8b75133f4c27321464b2197507f))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.9.0 ([#683](https://github.com/descope/go-sdk/issues/683)) ([3ca81e8](https://github.com/descope/go-sdk/commit/3ca81e822bc91e7323985afc5cec9e30af9cc773))
* project snapshot import exclude list ([e7f2a2e](https://github.com/descope/go-sdk/commit/e7f2a2eec631c6ec9c23b0951d508bff50065148))

## [1.9.0](https://github.com/descope/go-sdk/compare/v1.8.0...v1.9.0) (2026-02-17)


### Features

* add license handshake and header injection ([#681](https://github.com/descope/go-sdk/issues/681)) ([1e5c653](https://github.com/descope/go-sdk/commit/1e5c6532db410c267f59a2130cfa12673ca0a3c9))
* custom attributes for third party app [#682](https://github.com/descope/go-sdk/issues/682) ([89f234d](https://github.com/descope/go-sdk/commit/89f234d30b67cdaef67521d98cbd77c464e2ac94))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.8.0 ([#676](https://github.com/descope/go-sdk/issues/676)) ([c5abbff](https://github.com/descope/go-sdk/commit/c5abbff9f02883c709f156d55b4b788a043341c8))

## [1.8.0](https://github.com/descope/go-sdk/compare/v1.7.0...v1.8.0) (2026-02-03)


### Features

* added jwt leeway ([#675](https://github.com/descope/go-sdk/issues/675)) ([c6b7b43](https://github.com/descope/go-sdk/commit/c6b7b43d802d29fceb6f40dc21a6cb5a27e2d970))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.7.0 ([#669](https://github.com/descope/go-sdk/issues/669)) ([c0a03f4](https://github.com/descope/go-sdk/commit/c0a03f46f32a595609d992d85e6bd7a02ed554b4))

## [1.7.0](https://github.com/descope/go-sdk/compare/v1.6.23...v1.7.0) (2026-01-19)


### Features

* access key custom attributes CRUD ([4b517c1](https://github.com/descope/go-sdk/commit/4b517c126370f469c78bf74f7aa146cd28c449e4))


### Bug Fixes

* add group priority support ([#665](https://github.com/descope/go-sdk/issues/665)) ([b5b0d4a](https://github.com/descope/go-sdk/commit/b5b0d4a8eec884a304a0d3bda75cc0c74e71f3e7))
* **deps:** update module github.com/descope/go-sdk to v1.6.23 ([#658](https://github.com/descope/go-sdk/issues/658)) ([0103c15](https://github.com/descope/go-sdk/commit/0103c155cf5dc9669ec52703a19b57f0179baf9b))
* recalculate SSO Mappings ([213a6cf](https://github.com/descope/go-sdk/commit/213a6cf53003c9f2c67539e6c565dd02737ffb28))
