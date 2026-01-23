# [2.1.0](https://github.com/filipo11021/nodejs-password-hashing/compare/v2.0.0...v2.1.0) (2026-01-23)


### Features

* add pepper support to argon2 hashing ([#34](https://github.com/filipo11021/nodejs-password-hashing/issues/34)) ([4d508df](https://github.com/filipo11021/nodejs-password-hashing/commit/4d508dfb97b24f82fb1932f7b0263be42ee357af))

# [2.0.0](https://github.com/filipo11021/nodejs-password-hashing/compare/v1.0.2...v2.0.0) (2026-01-21)

### Features

- **#33:** tree-shake unused drivers when importing single driver ([e0d7bf0](https://github.com/filipo11021/nodejs-password-hashing/commit/e0d7bf068ad3425e215115686dcdb2704d32915c)), closes [#33](https://github.com/filipo11021/nodejs-password-hashing/issues/33)

### BREAKING CHANGES

- **#33:** Root package exports have been removed. Import directly from subpaths instead:

Before:
import { createArgon2Hashing, createScryptHashing, Hashing, HashingDep } from '@filipo11021/nodejs-password-hashing'

After:
import { createArgon2Hashing } from '@filipo11021/nodejs-password-hashing/argon2'
import { createScryptHashing } from '@filipo11021/nodejs-password-hashing/scrypt'
import type { Hashing, HashingDep } from '@filipo11021/nodejs-password-hashing/contracts'

## [1.0.2](https://github.com/filipo11021/nodejs-password-hashing/compare/v1.0.1...v1.0.2) (2026-01-21)

### Bug Fixes

- **#31:** Options config type resolves to any instead of proper type inference ([73c551e](https://github.com/filipo11021/nodejs-password-hashing/commit/73c551e3c3657444940c4b19ce1a4547d511b715))

## [1.0.1](https://github.com/filipo11021/nodejs-password-hashing/compare/v1.0.0...v1.0.1) (2026-01-19)

### Bug Fixes

- include dist folder in published package ([#28](https://github.com/filipo11021/nodejs-password-hashing/issues/28)) ([001a6a5](https://github.com/filipo11021/nodejs-password-hashing/commit/001a6a5d17aada0e96e0e99e2ea513471813a542))

# 1.0.0 (2026-01-18)

### Bug Fixes

- add range validation for PHC formatter schema to prevent DoS ([e14a856](https://github.com/filipo11021/nodejs-password-hashing/commit/e14a856cefd8b3a8bec65ed03dd39f5e28cdc2d5))
- **argon2:** match PHC formatter id to the actual algorithm variant used ([58e7ac1](https://github.com/filipo11021/nodejs-password-hashing/commit/58e7ac1d3e749a6889c4fc36a826cd7abe4f4296))
- **phc-formatter:** resolve type mismatch, correctly infer type of version ([f04af05](https://github.com/filipo11021/nodejs-password-hashing/commit/f04af05d6d6a1ffe62d00b64cbe3615cfd1f362d))
- **phc-formatter:** update main test flow to use version field ([0682a0a](https://github.com/filipo11021/nodejs-password-hashing/commit/0682a0a139ff848b601fcea87514f20a6a84ce85))
- prevent exception-based attacks with malformed hash input ([13006a6](https://github.com/filipo11021/nodejs-password-hashing/commit/13006a6300be9e9541ee912131185683bbbc0f75))
- run tests from nested directories ([ed7bb4d](https://github.com/filipo11021/nodejs-password-hashing/commit/ed7bb4de72f4f90b711c83944ae57a4a40f9b934))

### Features

- **#10:** implement automated release flow with semantic-release ([#14](https://github.com/filipo11021/nodejs-password-hashing/issues/14)) ([db9edd3](https://github.com/filipo11021/nodejs-password-hashing/commit/db9edd3432cfab454db8647e0e65931958d9fd5d)), closes [#10](https://github.com/filipo11021/nodejs-password-hashing/issues/10)
- **#2:** Add version support to Argon2 hashing and remove unnecessary phc formatter abstraction ([de3ad30](https://github.com/filipo11021/nodejs-password-hashing/commit/de3ad300f47190d8ddc6bb2d81f401ad68f7cb6f)), closes [#2](https://github.com/filipo11021/nodejs-password-hashing/issues/2)
- **#3:** Make salt size configurable ([84fe6d4](https://github.com/filipo11021/nodejs-password-hashing/commit/84fe6d47b3dcc4f51c7864ff816830a4de70fd00)), closes [#3](https://github.com/filipo11021/nodejs-password-hashing/issues/3)
- **#4:** Use standard parameter names in PHC format ([41a2712](https://github.com/filipo11021/nodejs-password-hashing/commit/41a271248ef2c2a1b59a207875d631c53a3605b2)), closes [#4](https://github.com/filipo11021/nodejs-password-hashing/issues/4)
- **#5:** Validate options when creating hashing instance ([cd303be](https://github.com/filipo11021/nodejs-password-hashing/commit/cd303bef7b3d6a143f798803dd5991b660130f1b)), closes [#5](https://github.com/filipo11021/nodejs-password-hashing/issues/5)
- add test coverage script ([42b5045](https://github.com/filipo11021/nodejs-password-hashing/commit/42b50450960a320a4ccbe8a74fb7e1cb338fd834))
- detect hashes created with different configuration ([0ac626d](https://github.com/filipo11021/nodejs-password-hashing/commit/0ac626d6cc6279236a575d26fe435aa0be06ebbb))
