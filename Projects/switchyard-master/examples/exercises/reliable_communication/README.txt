Zhenyuan Shen 9073728355
Wuyue Liu 9071787742

Description of the blaster:

The blaster sequentially sends/receives packets while maintains a slide window and a non-ACKed packet list dynamically
until it hits the slide window constraint or timeout occurs. Upon coarse timeout occurs, the blaster will reset the timer,
take a snapshot of current non-ACKed packet as a retransmission list and at each recv_time loop, pop the first packet in
the retransmission list and resend it till the list is empty or timeout occurs again.

During the retransmissions:
(1) LHS, non-ACKed list and retransmission list may update when new ACK arrives; (2) if timeout occurs again, update
retransmission list to the current non-ACKed list and repeat the retransmission process.

After retransmissions:
Send next packet and update RHS if not violating the constraints and so on.
