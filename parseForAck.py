#!/usr/bin/env python
# python 2
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, optparse

# Purpose: Scan a pcap and check for all dropped packets
# If syn found, grab sport
# Add port and predicted sequence number to dictionary
# Iterate through dictionary each time
# When ack with the same sport is found
# Print "Found Match!"
# The unmatched packets can be considered fragmented 

numberOfMatches = 0
synCount        = 0
syn             = {}

def analyzer(pcap):
    parameters = {"pcap":pcap}
    
     #if "pcap" not in parameters or parameters["pcap"] is None:
    #    sys.exit("\nNo PCAP Specified - see usage\n")
    
    global SYN, ACK
    SYN     = 0x02
    ACK     = 0X10
    SYN_ACK = 0x12
    
    # Iterate over pcap
    myReader = PcapReader(parameters["pcap"])
    for p in myReader:
        pkt = p.payload       
        payload = pkt[TCP].payload
        
        global pkt_size, numberOfMatches, synCount
        pkt_size = len(payload)

        if TCP not in p:
            continue
        
        # Grab ip number for source and destination of each packet
        if IP in pkt:
            ip_src  = pkt[IP].src
            ip_dst  = pkt[IP].dst
            if ((pkt[IP].src == "192.168.1.1") or (pkt[IP].src == "192.168.1.10")):
                print "\nPhantom spotted\n"
            
        if TCP in pkt:                              # Check that it is a tcp packet
            tcp_sport   = pkt[TCP].sport            # Store the source port
            tcp_dport   = pkt[TCP].dport            # Store the destination port
            seqNum      = pkt.getlayer(TCP).seq     # Grab the packet sequence number 
            nextSeqNum  = seqNum + pkt_size + 1     # Predict the ACK sequence number
            
        F = p['TCP'].flags # Check for TCP flags
        # Add all SYN packets to a dictionary
        if F & SYN:
            #print "\nSYN flag found!"
            syn.update({tcp_sport : nextSeqNum})
            synCount += 1
            
        if F & ACK:
            #print "\nACK flag found!"
            for port, seq in syn.iteritems():
                if port == tcp_sport: # port = port number
                    if seq == seqNum: # Compare the predicted ACK number to the actual
                        #print "\nMatch found!"
                        #print "Expected seq num:  %d" %(seq)
                        #print "Found seqNum:      %d" %(seqNum)
                        #print "Number of matches: %d" %(numberOfMatches)
                        numberOfMatches += 1
           
        """if F & SYN_ACK:
            print "\nSYN/ACK handshake found!" """
     
def printReport():
    fragmentedPackets = synCount - numberOfMatches
    print "\n******************************************"
    print "\tSyn Count:                  %d" %(synCount)
    print "\tMatching Acks:              %d" %(numberOfMatches) 
    print "\tTotal fragmented packets:   %d" %(fragmentedPackets)
    print "******************************************"

def main(pcap):
    analyzer(pcap)
    printReport()
    
#if __name__ == '__main__':
#    main()
    
    
    
