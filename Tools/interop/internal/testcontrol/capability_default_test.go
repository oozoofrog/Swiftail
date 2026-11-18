// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Origin: copied from tailscale.com v1.104.6 tstest/integration/testcontrol/capability_default_test.go (license: LICENSE in this directory).
// Changes are marked "Differs from upstream" or "Added here." See the tailnet section of Tools/interop/README.md for the list.

// Differs from upstream: removed the build tag because the experiment.reco alternate implementation (reco-experiment.go) was not copied.

package testcontrol_test

// The original test server also implements legacy map protocol versions.
const minTestControlCapabilityVersion = 0
