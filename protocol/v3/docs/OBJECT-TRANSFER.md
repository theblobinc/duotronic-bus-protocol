# Resumable Object Transfer

Large objects use a content-addressed manifest: object name/type, total size, chunk size and SHAKE256-512 digest for each chunk. Individual chunks can arrive out of order, through multiple paths, or after reconnect. A chunk is accepted only when its digest matches the manifest.

Applications may additionally bind the manifest to a Witness evidence object, signature or authority event. Resume state is a list/bitmap of verified chunks, never a claim that unverified bytes are present.

Implementations enforce hard total-object and in-flight byte limits and authenticated declared decompression expansion limits.
