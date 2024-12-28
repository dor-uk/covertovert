from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, sniff
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        

    def send(self, log_file_name, source_ip, destination_ip, message_min_length, message_max_length, mul1, mul2):
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, message_min_length, message_max_length)

        sum = 0
        sum2 = 0
        count = 1
        t1 = time.time()
        for bit in binary_message:
            sum2 = sum + int(bit)
            if sum2 == sum:
                burst_count = mul1
            else:
                burst_count = mul2
            sum += int(bit)
            for _ in range(burst_count):
                packet = IP(src=source_ip, dst=destination_ip) / TCP(
                    flags="S" if bit == '0' else ""
                )
                super().send(packet)
            count += 1
        
        packet = IP(src=source_ip, dst=destination_ip) / TCP(flags="")
        super().send(packet)
        t2 = time.time()
        total_time = t2 - t1
        capacity = 128 / total_time

    def receive(self, log_file_name, destination_ip, mul1, mul2):
        received_bits = []
        decoded_message = ""
        current_burst = 0
        current_flag = None
        stop_sniffing = False

        def packet_handler(packet):
            nonlocal received_bits, decoded_message, current_burst, current_flag, stop_sniffing

            if packet.haslayer(TCP) and packet[IP].dst == destination_ip:
                syn_flag = packet[TCP].flags & 0x02

                if current_flag is None:
                    current_flag = syn_flag

                if syn_flag == current_flag:
                    current_burst += 1
                else:
                    if current_flag:
                        if current_burst % mul1 == 0:
                            inc_num = 0
                            while inc_num < current_burst:
                                received_bits.append('0')
                                inc_num += mul1
                    else:
                        if current_burst % mul2 == 0:
                            inc_num = 0
                            while inc_num < current_burst:
                                received_bits.append('1')
                                inc_num += mul2

                    current_burst = 1
                    current_flag = syn_flag

                if len(received_bits) >= 8:
                    byte = "".join(received_bits[:8])
                    char = self.convert_eight_bits_to_character(byte)
                    decoded_message += char
                    received_bits = received_bits[8:] 

                    if char == '.':
                        stop_sniffing = True

                

        def stop_filter(pkt):
            return stop_sniffing
        sniff(filter=f"ip dst {destination_ip}", prn=packet_handler, stop_filter=stop_filter)
        

        self.log_message(decoded_message, log_file_name)
        

        return decoded_message

