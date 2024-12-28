
# Covert Storage Channel using TCP SYN Flag Manipulation

### Overview

This project implements a covert storage channel that exploits protocol field manipulation by using the SYN flag field in the TCP header. The channel allows for covert communication by encoding binary messages into the TCP flags of outgoing packets. The implementation follows the `CSC-PSV-TCP-SYN` methodology.

The Methods We Have Used Are:
- - -
- - -
- - -
### `send`

#### Logic of Sending Message
Binary messages are sent using the following rule:
- A cumulative sum is maintained during message transmission. For the purpose of determining if a bit is zero or one.

- If the cumulative sum didn't change when the current bit of the message is added, this corresponds to binary bit zero. Then, we send TCP packets multiple of given first parameter (mul1) with the SYN flag set (flags="S").

- If the cumulative sum changed when the current bit of the message is added, this corresponds to binary bit one. Then, we send TCP packets multiple of given second parameter (mul2) without the SYN flag (flags="").

- - -
- - -
- - -

### `receive`

#### Logic of Receiving Message
The function uses a nested packet_handler to process packets and filter those destined for the specified destination_ip. It checks if the packet has a TCP layer and matches the destination IP.

- The TCP SYN flag is extracted (packet[TCP].flags & 0x02).
- If it's the first packet, current_flag is set to the detected flag value.
- The current_burst counter increments as long as packets with the same flag type continue arriving.

When the flag changes (from SYN to non-SYN or vice versa):
- If the flag was SYN (current_flag is True), the burst length (current_burst) is checked against mul1. For every mul1 packets in the burst, a '0' bit is appended to received_bits.
- If the flag was not SYN (current_flag is False), the burst length is checked against mul2. For every mul2 packets in the burst, a '1' bit is appended to received_bits.

Then, reconstruct the original message, then print it.

- - - 
- - -
- - -

### `Capacity of the Covert Channel`
Capacity: 14.37 bits/second
For mul1 being 3, mul2 being 2
Change in these parameters result in change in capacity

To measure the capacity, we followed these steps:
    
    1. Create a binary message whose length is 128.
    2. Start the timer just before sending the first packet.
    3. Finish the timer, just after sending the last packet.
    4. Find the difference in seconds.
    5. Divide 128 by the calculated time in seconds.


### Limitations
- The system relies on bursts of TCP packets, with bits being encoded based on the number of packets in each burst. This inherently limits the amount of data that can be transmitted efficiently.
- The decoding process is highly dependent on the mul1 and mul2 values. Incorrect values can lead to errors in interpreting the message.

### Parameters
- mul1: The multiplier used to interpret bursts of packets with a SYN flag ('0' bit).
- mul2: The multiplier used to interpret bursts of packets without a SYN flag ('1' bit).





