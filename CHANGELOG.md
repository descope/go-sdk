# Changelog

## [1.23.0](https://github.com/descope/go-sdk/compare/v1.22.0...v1.23.0) (2026-06-20)


### Features

* **otp:** add MFA option to OTP update phone/email ([#772](https://github.com/descope/go-sdk/issues/772)) ([dc36a25](https://github.com/descope/go-sdk/commit/dc36a257b9ed8f336fe0dde753a6ef8c3d4b2a1e))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.22.0 ([#770](https://github.com/descope/go-sdk/issues/770)) ([9e63c56](https://github.com/descope/go-sdk/commit/9e63c56da318db6918ea63eea1c72c714f40a888))

## [1.22.0](https://github.com/descope/go-sdk/compare/v1.21.0...v1.22.0) (2026-06-18)


### Features

* add SSO OIDC dedicated client config, secret get/rotate, and force-PKCE ([#759](https://github.com/descope/go-sdk/issues/759)) ([84d1056](https://github.com/descope/go-sdk/commit/84d105604d567629f811c2e46e2951a275d81395))
* **tenant:** bind a real user to GenerateSSOConfigurationLink for correct audit actor ([#769](https://github.com/descope/go-sdk/issues/769)) ([af00fa5](https://github.com/descope/go-sdk/commit/af00fa501761eb8ab04d207a2b7276c443da450c))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.21.0 ([#766](https://github.com/descope/go-sdk/issues/766)) ([3920559](https://github.com/descope/go-sdk/commit/39205593f57ce2bcaca325e1cdd57eeb21f2d76c))

## [1.21.0](https://github.com/descope/go-sdk/compare/v1.20.0...v1.21.0) (2026-06-12)


### Features

* add DPoP Proof Validation (RFC 9449) ([#737](https://github.com/descope/go-sdk/issues/737)) ([11a3361](https://github.com/descope/go-sdk/commit/11a3361fffd9f008583f330e93c63b3a7f518e8b))
* add new passkey management APIs ([#751](https://github.com/descope/go-sdk/issues/751)) ([781ae78](https://github.com/descope/go-sdk/commit/781ae7800fa89577f2a9d81242344beb8a7698a8))
* **mgmt:** add ReplyAllowedCallbacks to WS-Fed application request ([#755](https://github.com/descope/go-sdk/issues/755)) ([0f05b50](https://github.com/descope/go-sdk/commit/0f05b501a465db2621c4cd373c35655489a655c9))
* **security:** dpop JTI replay protection ([#757](https://github.com/descope/go-sdk/issues/757)) ([9423f21](https://github.com/descope/go-sdk/commit/9423f217e12eaac40c2cf3fcf565f1e38be76940))
* **sso:** add IdP entityId to ConfigureSAMLSettingsByMetadata ([#764](https://github.com/descope/go-sdk/issues/764)) ([78c5891](https://github.com/descope/go-sdk/commit/78c5891b0cea74abe589335ed573a91ba57280e6))
* **user:** add locale option to invite and invite-batch ([#758](https://github.com/descope/go-sdk/issues/758)) ([5537f8c](https://github.com/descope/go-sdk/commit/5537f8ceaea43d4a7b089a8ba5e6c7cfaa7aff7f))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.20.0 ([#749](https://github.com/descope/go-sdk/issues/749)) ([08119bd](https://github.com/descope/go-sdk/commit/08119bd686e0d55e296a382b23d7b0ae7aaa9af1))
* **deps:** update module github.com/gin-gonic/gin to v1.12.0 ([#715](https://github.com/descope/go-sdk/issues/715)) ([5452d07](https://github.com/descope/go-sdk/commit/5452d07ffc023b7f9f48d82811b4ac81c862e9b7))

## [1.20.0](https://github.com/descope/go-sdk/compare/v1.19.0...v1.20.0) (2026-05-14)


### Features

* update license handshake to use rateLimitTier ([#692](https://github.com/descope/go-sdk/issues/692)) ([eaee953](https://github.com/descope/go-sdk/commit/eaee953029cbb0c1579f0311bef265bad2cc87bd))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.19.0 ([#746](https://github.com/descope/go-sdk/issues/746)) ([91cb456](https://github.com/descope/go-sdk/commit/91cb45671d6d95025862e8c4a2856411e8331db7))

## [1.19.0](https://github.com/descope/go-sdk/compare/v1.18.0...v1.19.0) (2026-05-11)


### Features

* add UpdateWithID and DeleteWithID for roles and permissions ([#740](https://github.com/descope/go-sdk/issues/740)) ([3586dc6](https://github.com/descope/go-sdk/commit/3586dc6cd225b5a393d11534b5eb65412a3692d9))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.18.0 ([#744](https://github.com/descope/go-sdk/issues/744)) ([f35b1a8](https://github.com/descope/go-sdk/commit/f35b1a8cbabf647190b0049be353a033f3574a8d))

## [1.18.0](https://github.com/descope/go-sdk/compare/v1.17.0...v1.18.0) (2026-05-09)


### Features

* add TenantUserIsolation support with TenantID in auth options ([#736](https://github.com/descope/go-sdk/issues/736)) ([1e1ef92](https://github.com/descope/go-sdk/commit/1e1ef9279a67d73b22fd37222b113dc09a1154d2))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.17.0 ([#734](https://github.com/descope/go-sdk/issues/734)) ([1245b29](https://github.com/descope/go-sdk/commit/1245b297c94c80178b5d254227733547ccde3ebc))

## [1.17.0](https://github.com/descope/go-sdk/compare/v1.16.0...v1.17.0) (2026-04-20)


### Features

* add IDPResponse to AuthenticationInfo for SSO exchange ([#733](https://github.com/descope/go-sdk/issues/733)) ([fdf2e9a](https://github.com/descope/go-sdk/commit/fdf2e9ad29cd49335e561a5f2659d5b8464a81b1))


### Bug Fixes

* **deps:** update module github.com/descope/go-sdk to v1.16.0 ([#730](https://github.com/descope/go-sdk/issues/730)) ([c3b476d](https://github.com/descope/go-sdk/commit/c3b476df0dd5222f5a66c1f9f999570c92913ca3))

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
