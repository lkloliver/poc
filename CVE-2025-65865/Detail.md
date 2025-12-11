##  Vulnerability Details

### 1. Specific Location of Vulnerable Code

```cpp
//./Fast-DDS/src/cpp/rtps/messages/MessageReceiver.cpp
bool MessageReceiver::proc_Submsg_DataFrag(
......
//1028行
payload_size = smh->submessageLength - (RTPSMESSAGE_DATA_EXTRA_INLINEQOS_SIZE + octetsToInlineQos + inlineQosSize);
......
```

The integer overflow occurs at line 1028.

`RTPSMESSAGE_DATA_EXTRA_INLINEQOS_SIZE` is a constant defined as 4, representing the length of the `inlineQos` termination identifier.

`smh->submessageLength` is derived from the `octstsToHeader` field in the message.

`octetsToInlineQos` is derived from the field of the same name in the message.

`inlineQosSize` is derived from the field of the same name in the message.

### 2. Direct Cause of the Vulnerability

`smh->submessageLength` is only checked at line 920 at the entry point of the `proc_Submsg_DataFrag` function to ensure it is not less than `RTPSMESSAGE_DATA_MIN_LENGTH` (constant 24, the minimum length of the message excluding the `header`).

```cpp
//./Fast-DDS/src/cpp/rtps/messages/MessageReceiver.cpp
bool MessageReceiver::proc_Submsg_DataFrag(
......
//920行
if (smh->submessageLength < RTPSMESSAGE_DATA_MIN_LENGTH)
{
    ......
    return false;
}
......
```

`octetsToInlineQos` is only compared at line 1000, and in practice its value generally does not exceed `RTPSMESSAGE_OCTETSTOINLINEQOS_DATAFRAGSUBMSG` (constant 28, representing the total length of fields between the `inlineQos` field and the `octetsToInlineQos` field in a `data_frag` type message).

```cpp
//./Fast-DDS/src/cpp/rtps/messages/MessageReceiver.cpp
bool MessageReceiver::proc_Submsg_DataFrag(
......
//1000行
if (octetsToInlineQos > RTPSMESSAGE_OCTETSTOINLINEQOS_DATAFRAGSUBMSG)
{
    msg->pos += (octetsToInlineQos - RTPSMESSAGE_OCTETSTOINLINEQOS_DATAFRAGSUBMSG);
    if (msg->pos > msg->length)
    {
        .....
        return false;
    }
}
......
```

`inlineQosSize` has strict length control due to the presence of the `inlineQos` termination identifier.

This creates a scenario: if the value of `octstsToHeader` in the input message is greater than 24 but less than 4 + the value of `octetsToInlineQos` + the value of `inlineQos`, it can cause `payload_size` to underflow.

At this point, since `msg->pos` has already finished reading the content of `inlineQos`, the pointer is located after `inlineQos`, so its value is 4 + the value of `octetsToInlineQos` + the value of `inlineQos` + the length of the submessage `header` (1 (`submessage ID`) + 1 (`Flags`) + 2 (`octstsToHeader`) + 2 (`Extra flags`) = 6).

```cpp
//./Fast-DDS/src/cpp/rtps/messages/MessageReceiver.cpp
bool MessageReceiver::proc_Submsg_DataFrag(
......
//1015行
if (!ParameterList::updateCacheChangeFromInlineQos(ch, msg, inlineQosSize))
......
```

At this point, the value of `next_pos` will overflow again and return to a normal numeric range, with a value of `smh->submessageLength` + 6. In the following `if` check, the value of `msg->length` is not read from a field but directly obtained from the buffer length, so as long as the actual `Data_frag` submessage length is greater than the value of the `octstsToHeader` field + 6, it can pass the `if` check.

```cpp
//./Fast-DDS/src/cpp/rtps/messages/MessageReceiver.cpp
bool MessageReceiver::proc_Submsg_DataFrag(
......
//1030行
uint32_t next_pos = msg->pos + payload_size;
if (msg->length >= next_pos && payload_size > 0)
{
    ch.serializedPayload.data = &msg->buffer[msg->pos];
    ch.serializedPayload.length = payload_size;
    ch.serializedPayload.max_size = payload_size;
    ch.serializedPayload.is_serialized_key = keyFlag;
    ch.setFragmentSize(fragmentSize);

    msg->pos = next_pos;
}
......
```

The expression `&msg->buffer[msg->pos]` is used to obtain the `payload` field in the message. At this point, the `msg->pos` pointer is located after the `inlineQos` termination identifier. When `payload` does not exist, an attacker can bypass the condition check and enter this `if` branch by constructing an integer underflow, which will cause `&msg->buffer[msg->pos]` to access memory regions outside the legitimate submessage boundary. At this point, the `length` field will be set to a very large value close to the upper limit of `uint32_t`, and the `fragmentSize` field will be saved without any validity check.

```cpp
// ./Fast-DDS/include/fastdds/rtps/common/CacheChange.hpp
bool add_fragments(
......
//288行
uint32_t incoming_length = fragment_size_ * fragments_in_submessage;
......
//323行
memcpy(
        &serializedPayload.data[original_offset],
        incoming_data.data, incoming_length);
......
```

The `add_fragments` function is called once when processing each message, where `fragments_in_submessage` represents the number of `data_frag` submessages carried in the current message, and `fragment_size_` represents the declared length of each fragment. However, the value of `fragment_size_` is not derived from the actual fragment data length, but is directly read from the `fragmentSize` field in the message (occupying 2 bytes), which can be arbitrarily specified by an attacker. Taking the `RTPS` data packet constructed by this `POC` as an example, by setting 0x330 `frag` submessages, the calculated `incoming_length` value reaches 0x32ffcd0 (approximately 53MB). Since `memcpy` performs copy operations in address-ascending order, when copying such an enormous illegal length, it is highly likely to access invalid memory regions outside the process's legitimate address space, thereby triggering a segmentation fault.

It should be noted that the theoretical upper limit of the copy length for `original_offset` is constrained by the `samplesize` field in the message (occupying 4 bytes, representing the total message length), with a maximum value of 0xffffffff (approximately 4GB). Therefore, in the worst-case attack scenario, `memcpy` may access arbitrary memory regions extending up to 0xffffffff bytes from the legitimate submessage starting position, causing a serious out-of-bounds read vulnerability.

### 3. Indirect Causes of the Vulnerability

#### 1
Since `msg->length` is the actual buffer length, when the value of `octstsToHeader` is less than the actual submessage length, the loop at line 418 will continue because the reading is not complete. However, according to the assignment at line 592, `msg->pos` is not at the actual reading position after processing a submessage, but moves to the first byte of the next submessage based on the value of `octstsToHeader`.

```cpp
//./Fast-DDS/src/cpp/rtps/messages/MessageReceiver.cpp
void MessageReceiver::processCDRMsg(
...... 
//418行
while (msg->pos < msg->length)
......
//446行
    uint32_t next_msg_pos = submessage->pos;
    next_msg_pos += (submsgh.submessageLength + 3u) & ~3u;
......
//592行
	submessage->pos = next_msg_pos;
......
```

Additionally, if the parameter `ID` of `inlineQos` content is not in the `case` list, it will pass without content checking.

```cpp
//./Fast-DDS/src/cpp/fastdds/core/policy/ParameterList.cpp
bool ParameterList::updateCacheChangeFromInlineQos(
......
//157行
	default:
        break;
}

return true;
......
```

Therefore, the actual content of `inlineQos` can be replaced with a submessage that does not affect other content but has a valid structure, such as an `Info_TS` submessage (which only provides the current timestamp). Then, by precisely constructing the value of `octstsToHeader` so that the calculated value of `msg->pos` exactly falls on the first byte of this constructed `inlineQos`, the check can be bypassed and pass normally.

At the end of `inlineQos`, there is a mandatory 4-byte termination identifier with the content 0x01, 0x00, 0x00, 0x00. The value 0x01 happens to have a corresponding `case` in the submessage identification loop, which is `PAD`, but this `case` is not yet implemented, so it will pass directly. The 0x00 case will also pass directly for that byte.

```cpp
//./Fast-DDS/src/cpp/rtps/messages/MessageReceiver.cpp
void MessageReceiver::processCDRMsg(
......
//559行
case PAD:
    break;
......
//583行
default:
    break;
......
```

#### 2
`fastdds` uses `qos` partitioning only during the discovery phase, when `accept_messages_from_unkown_writers_` is `true`. After matching a publisher, `accept_messages_from_unkown_writers_` is set to `false`, but the `qos` policy is also no longer used. As can be seen from the code, during normal communication, subscribers only determine whether to accept a message based on the `entityId` and `guid` of the `writer` in the data packet. Therefore, as long as the `guid` and `entityId` of a `writer` are captured from a normal communicating subscriber/publisher pair, a data packet can be constructed that bypasses the `qos` policy and is directly received by the subscriber. However, if shared memory mode is used, this cannot be used because monitoring is not possible.
```cpp
//./Fast-DDS/src/cpp/rtps/reader/StatelessReader.cpp
//889 行
bool StatelessReader::acceptMsgFrom(
        const GUID_t& writerId,
        ChangeKind_t change_kind)
{
    if (change_kind == ChangeKind_t::ALIVE)
    {
        if (accept_messages_from_unkown_writers_)
        {
            return true;
        }
        else if (writerId.entityId == trusted_writer_entity_id_)
        {
            return true;
        }
    }

    return std::any_of(matched_writers_.begin(), matched_writers_.end(),
                   [&writerId](const RemoteWriterInfo_t& writer)
                   {
                       return writer.guid == writerId;
                   });
}
```
## Vulnerability Exploitation
### Exploitation Conditions
Network Reachability: The attacker needs to be able to send maliciously constructed RTPS data packets to the target FastDDS instance
Port Access: Access to the default port range for DDS communication (7400-7500)
Information Gathering: The GUID and entityId information of writers in normal communication in the target system needs to be obtained, therefore the target system needs to use UDP communication
### Severity
As long as an attacker can monitor other people's writer information, they can easily cause other people's subscriber endpoints to crash, which has high severity.
