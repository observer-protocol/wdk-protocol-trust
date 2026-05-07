// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Bare runtime entry. The module's surface is the same as the Node entry
// (index.js); we re-export here so Bare consumers can resolve the package
// via the "bare" condition in package.json's exports map.

'use strict'

export * from './index.js'
export { default } from './index.js'
