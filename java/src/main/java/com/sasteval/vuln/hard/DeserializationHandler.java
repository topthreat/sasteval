package com.sasteval.vuln.hard;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

/**
 * CWE-502: Deserialization of Untrusted Data
 * VULNERABILITY: Deserializes arbitrary bytes with no type filter or allowlist.
 */
public class DeserializationHandler {

    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        // VULN: No ObjectInputFilter, no type checking — arbitrary class instantiation
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
