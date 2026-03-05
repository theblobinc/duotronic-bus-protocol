# Duotronic Bus Protocol (DBP)

| | |
|---|---|
| **Version:** | `v1.1` (Recommended Baseline) |
| **Status:** | Stable |
| **Format:** | Fixed-offset 4096-byte binary frame |
| **Core Type:** | IEEE 754 `binary32` (single-precision float) |

<br>

**Why should data be a dimensionless number? DBP re-imagines real-time communication by treating information as a physical property with inherent geometry, context, and probabilistic nature.**

The Duotronic Bus Protocol is an architecturally unique, fixed-size (4096-byte) binary protocol for broadcasting complex, heterogeneous state. Instead of separating data by message boundaries, DBP multiplexes it by position within a single, contiguous `Float32Array` frame, analogous to frequency-division multiplexing in radio.

This approach is designed for extreme performance in one-to-many "fan-out" systems, enabling constant-time, zero-allocation decoding on the client. It provides a unified data model for applications that need to communicate continuous signals, discrete messages, and predictive probabilities simultaneously.

At its most profound, DBP provides the data structure for building advanced cybernetic and AI systems, serving as a visible "stream of consciousness" or a high-bandwidth nervous system for feedback loops.

<br>
<hr>

<p align="center">
  <img src="./spec/digital-witness.png" alt="Duotronic Digital Witness for the integer 42" width="800"/>
  <br>
  <b>Figure 1:</b> A Duotronic Digital Witness for the integer 42. In the optional Duotronic Math layer, a value is not stored directly; it is the calculated result of a defined geometric structure. This object <em>is</em> 42 in its complete context.
</p>

<hr>
<br>

## Core Philosophy

DBP's design is an exercise in **architectural unification**. Modern real-time systems often require a messy combination of technologies to function:
* A WebSocket or SSE stream for low-latency text messages.
* A separate polling endpoint for periodic status updates.
* Another high-frequency channel for raw visualization data.
* A connection to a vector database for similarity-based lookups.

DBP replaces this entire complex stack with a single, elegant primitive: **the frame**. The frame is the transport layer, the state snapshot, and the vector embedding, all in one.

This is achieved by accepting intentional **complexity debt** in the protocol itself to achieve extreme simplicity in the application and transport layers. The cost is paid once at design time, not continuously at runtime.

## Key Features

* **Fixed-Size Binary Frames:** Exactly 4096 bytes per frame. This provides predictable performance and eliminates all framing ambiguity, length-prefix parsing, and buffer re-allocation.
* **Positional Multiplexing:** Data is not found by name, but by its fixed position. Analog, digital, and quantum data live in dedicated "bands" at constant offsets, enabling zero-overhead decoding.
* **The Quantum Register:** A first-of-its-kind probabilistic state channel. It's a 64-qubit band for transmitting predictions, uncertainties, confidence scores, and other "quantum-inspired" metadata using real-valued amplitude pairs.
* **Cryptographically Secure:** A robust S1 security profile provides authenticity and anti-replay protection using an integrated 256-bit HMAC-SHA-256 tag and monotonic counters, with domain separation to prevent cross-protocol attacks.
* **AI & Vector Native:** A DBP frame *is* a 1024-dimensional `Float32` vector. This makes the protocol's output directly compatible with vector databases (e.g., Qdrant, Weaviate, Pinecone) for similarity search, anomaly detection, and providing a "long-term memory" for AI systems.
* **Transport Agnostic:** The specification is designed to work over any binary-capable channel. The recommended deployment patterns include highly scalable static file polling (`HTTP GET` with `ETag`), Server-Sent Events (SSE), and WebSockets.

## Use Cases

DBP excels in one-to-many broadcast scenarios where a single source of truth is fanned out to numerous viewers, and the state is a complex mixture of data types.

* **Real-Time Dashboards:** A live audio player dashboard showing track progress (analog), song titles (digital), and a live waveform visualization (analog), all from a single frame.
* **Financial Market Data Feeds:** Broadcasting stock charts (analog), scrolling news headlines (digital), and volatility predictions (quantum) to thousands of trader terminals.
* **Multiplayer Game Spectator Clients:** Sending a condensed game state for a spectator UI, including player health (analog), kill feeds (digital), and the probability of a critical event succeeding (quantum).
* **Industrial IoT & SCADA Monitoring:** A central server broadcasting factory floor status—machine temperatures (analog), error codes (digital), and predicted failure probabilities (quantum)—to operator displays.
* **AI System Telemetry:** An AI or SRNN "thinking out loud" by publishing its internal state, predictions, and uncertainties in a DBP stream for real-time observation, debugging, and learning.

## How It Works: The Anatomy of a Frame

A DBP frame is a `Float32Array` of 1024 cells (4096 bytes), organized into bands. The recommended `v1.1` layout is:

| Band | Cells | Size | Purpose |
|---|---|---|---|
| **Band 0** | `0–8` | 36 bytes | **Sync Header:** Magic number, version, 48-bit sequence, 64-bit timestamp, flags. |
| **Band 1** | `9–19` | 44 bytes | **Analog Control Lattice:** 11 general-purpose continuous float channels. |
| **Band 2** | `20–83` | 256 bytes | **Digital Channel A:** Carries up to 168 bytes of chunked, checksummed payload. |
| **Band 3** | `84–147` | 256 bytes | **Digital Channel B:** A second independent digital channel. |
| **Band 4** | `148–275` | 512 bytes | **Quantum Register:** 64 qubits (128 floats) for probabilistic state. |
| **Band 5** | `276–659`| 1536 bytes| **Analog Waveform/Digest:** High-volume continuous signal data or FFT digest. |
| **Band 6** | `660–999`| 1360 bytes| **Client Slot:** Primarily used for client-to-server `uplink` commands. |
| **Band 6T**| `1000–1019`| 80 bytes | **Security Trailer:** Contains anti-replay counters and a 256-bit HMAC tag. |
| **Band 7** | `1020–1023`| 16 bytes | **Frame Check:** 32-bit CRC, frame size, and magic number echo for integrity. |

### Transport Architecture

The protocol is transport-agnostic, but the primary deployment model uses a clever, highly scalable architecture that decouples the application writer from the delivery layer.

```
Writer (1 process) Static server (nginx) Clients (N)
┌──────────────┐ ┌────────────────────┐ ┌───────────────┐
│ Build frame │──write──▶│ /dbp/live/frame.bin │◀──GET─│ Conditional │
│ every tick │ │ 4096 bytes │─304/─▶│ poll (ETag) │
│ (atomic swap) │ │ ETag + Last-Modified│ 200 │ every Nms │
└──────────────┘ └────────────────────┘ └───────────────┘
```
This "static file relay" costs only one application process regardless of client count. The heavy lifting of fanning out the data is handled by a hyper-efficient web server like `nginx`, which returns tiny `304 Not Modified` responses when the frame hasn't changed. For lower latency, this can be upgraded to an SSE or WebSocket relay.

## The Quantum Register: A Deeper Look

The most unique feature of DBP is Band 4. It treats probability not as a raw number, but as a "quantum-inspired" state represented by a **qubit**. Each qubit is a pair of `Float32` amplitudes, `[α, β]`, corresponding to the state:

$$
|\psi\rangle = \alpha|0\rangle + \beta|1\rangle
$$

This is a powerful metaphor for representing uncertainty and predictive state.

* **Superposition:** A qubit can represent that a system is in a mixed state (e.g., 67% likely to change, 33% likely to stay), not just a binary 0 or 1.
* **Measurement:** A client can "collapse" the superposition by calling a `measure()` function, which returns `0` or `1` weighted by the probability, allowing for probabilistic UI effects.
* **Entanglement:** The protocol defines rules for "entangling" qubits, where collapsing one influences the state of another—perfect for modeling correlated predictions.
* **Self-Awareness:** Special qubits are reserved for system metadata, like `freshness` (how old is this prediction?) and `observation_count` (how much has this prediction been tested?).

## Getting Started

An implementer's primary resource is the full technical standard. This document contains all normative rules, byte-level layouts, cryptographic specifications, and conformance data.

**➡️ [Read the Full DBP v1.1 Specification](./spec/duotronic-bus-spec-v1.1.md)**

Latest working protocol docs and references:
- **Protocol reference draft:** [./protocol/duotronic-bus.md](./protocol/duotronic-bus.md)
- **Duotronic Math v2 reference:** [./protocol/ref/duotronic-math-v2.md](./protocol/ref/duotronic-math-v2.md)
- **WSB2 reference encoder/decoder (JS):** [./protocol/wsb2_ref.mjs](./protocol/wsb2_ref.mjs)
- **WSB2 reference encoder/decoder (Python):** [./protocol/wsb2_ref.py](./protocol/wsb2_ref.py)

### Implementation

The core of any DBP implementation is correctly parsing and validating the 4096-byte frame.

#### Validation Pipeline

A compliant receiver **MUST** validate frames in a strict, fail-fast sequence:
1. **Shape & Numeric Checks:** Is it 4096 bytes? Does it contain any `NaN`, `Infinity`, or subnormal values?
2. **Header & Footer Checks:** Does the magic number match? Are integers within their valid ranges?
3. **CRC32 Check:** Does the CRC of the frame content match the value in the footer?
4. **Security Check:** If the security trailer is present, is the anti-replay counter valid and does the HMAC tag match?
5. **Band Decoding:** Only after all checks pass should the application decode the individual bands.

#### Conformance Testing

The specification includes **deterministic conformance vectors** (`§17`) for both Open mode and S1 Security mode. These provide known-good frame data and the expected cryptographic outputs (HMAC tag and CRC32 value). To validate your implementation, generate a frame with the specified inputs and assert that your output matches the golden values in the spec.

#### Zero-Copy Access Example (JavaScript)

DBP is designed for efficient, zero-allocation access via typed arrays.

```javascript
// On a little-endian host, this is a true zero-copy operation.
const buffer = await response.arrayBuffer();
const frame = new Float32Array(buffer);

// Access data by direct indexing - no parsing overhead.
// (decodeU16 is a helper function that validates the cell value per spec rules)
const magic = decodeU16(frame[0]);
const seqHi = decodeU24(frame[3]);
const seqLo = decodeU24(frame[2]);
const frameSequence = seqHi * 16777216 + seqLo;

console.log(`Received frame #${frameSequence}`);
```

## Project Status

The Duotronic Bus Protocol specification for `v1.1` is **complete and stable**. It is considered the definitive version of the `v1.x` protocol line and is recommended for all new implementations.

The specification includes all necessary details for building a compliant sender, receiver, and verifier. Future work will focus on creating reference implementations in various languages and building tooling (e.g., a "DBP Inspector" for debugging).
