package com.sasteval.sca;

import net.jpountz.lz4.LZ4Factory;

/**
 * SCA Reachability: CVE-2025-12183 is UNREACHABLE.
 * The lz4-java library is present, but no lz4 methods are ever called from
 * the benchmark. This is intended to remain an unreachable package-only case.
 */
public class Lz4Unreachable {

    // Library included for feature planned in v2

    public Lz4Unreachable() {
        // No lz4 methods are called
    }
}
