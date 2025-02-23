#
# Copyright (c) 2015 Regents of the SIGNET lab, University of Padova.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University of Padova (SIGNET lab) nor the 
#    names of its contributors may be used to endorse or promote products 
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author: Federico Favaro
# Version: 1.0.0
# NOTE: tcl sample tested on Ubuntu 12.04, 64 bits OS
#
#########################################################################################
##
## NOTE: This script uses the PHY model "Module/MPhy/BPSK" of NS-Miracle in addPosition
## with the module "MInterference/MIV" for the computation of interference. 
## These two modules is used in this script to demonstrate their compatibility with
## DESERT stack.
## If you decide to use Module/UW/PHYSICAL from DESERT, it is suggested to use also 
## Module/UW/INTERFERENCE (which is an extension of the one coming from NS-Miracle)
## Anyways, it is possibile to use Module/UW/INTERFERENCE with Module/MPhy/BPSK whereas
## it is not possibile to use MInterference/MIV with Module/UW/INTERFERENCE for compatibility
## reasons
##
########################################################################################
# ----------------------------------------------------------------------------------
# This script depicts a very simple but complete stack in which two nodes send data
# to a common sink. The second node is used by the first one as a relay to send data to the sink.
# The routes are configured by using UW/STATICROUTING.
# The application used to generate data is UW/CBR.
# ----------------------------------------------------------------------------------
# Stack
#             Node 1                         Node 2                        Sink
#   +--------------------------+   +--------------------------+   +-------------+------------+
#   |  7. UW/APPLICATION       |   |  7. UW/APPLICATION       |   |  7. UW/APP  | UW/APP     |
#   +--------------------------+   +--------------------------+   +-------------+------------+
#   |  6. UW/UDP               |   |  6. UW/UDP               |   |  6. UW/UDP               |
#   +--------------------------+   +--------------------------+   +--------------------------+
#   |  5. UW/STATICROUTING     |   |  5. UW/STATICROUTING     |   |  5. UW/STATICROUTING     |
#   +--------------------------+   +--------------------------+   +--------------------------+
#   |  4. UW/IP                |   |  4. UW/IP                |   |  4. UW/IP                |
#   +--------------------------+   +--------------------------+   +--------------------------+
#   |  3. UW/MLL               |   |  3. UW/MLL               |   |  3. UW/MLL               |
#   +--------------------------+   +--------------------------+   +--------------------------+
#   |  2. UW/CSMA_ALOHA        |   |  2. UW/CSMA_ALOHA        |   |  2. UW/CSMA_ALOHA        |
#   +--------------------------+   +--------------------------+   +--------------------------+
#   |  1. Module/MPhy/BPSK     |   |  1. Module/MPhy/BPSK     |   |  1. Module/MPhy/BPSK     |
#   +--------------------------+   +--------------------------+   +--------------------------+
#            |         |                    |         |                   |         |       
#   +----------------------------------------------------------------------------------------+
#   |                                     UnderwaterChannel                                  |
#   +----------------------------------------------------------------------------------------+

######################################
# Flags to enable or disable options #
######################################
set opt(trace_files)        1
set opt(bash_parameters)    0

#####################
# Library Loading   #
#####################
load libMiracle.so
load libMiracleBasicMovement.so
load libmphy.so
load libmmac.so
load libUwmStd.so
load libuwcsmaaloha.so
load libuwip.so
load libuwstaticrouting.so
load libuwmll.so
load libuwudp.so
load libuwapplication.so

#############################
# NS-Miracle initialization #
#############################
# You always need the following two lines to use the NS-Miracle simulator
set ns [new Simulator]
$ns use-Miracle

#Declare the use of a Real Time Schedule (necessary for the interfacing with real hardware)
if {[lindex $argv 2] == 1} {
    $ns use-scheduler RealTime
}

##################
# Tcl variables  #
##################
set opt(nn)                 1.0 ;# Number of Nodes
set opt(starttime)          5
if {[lindex $argv 2] == 1} {
	set opt(stoptime) 200
} else {
	set opt(stoptime) 10000
}
set opt(txduration)         [expr $opt(stoptime) - $opt(starttime)]

set opt(maxinterval_)       20.0
set opt(freq)               25000.0
set opt(bw)                 5000.0
set opt(bitrate)            4800.0
set opt(ack_mode)           "setNoAckMode"

set opt(txpower)            135.0 

set opt(rngstream)            1
set opt(pktsize)    125
set opt(cbr_period) 60
set opt(socket_comm) 0

if {$opt(bash_parameters)} {
    if {$argc != 4} {
        puts "ERROR!!!!!!"
		  puts "The script requires four inputs:"
        puts "---> The DATA packet size (byte)"
        puts "---> Period to generate DATA packets (s)"
        puts "---> socket_comm"
        puts "---> Random generator substream"
        puts "For example: ns test_uwApplication.tcl 125 60 0 13"
        puts "Please try again."
        return
    } else {
        if {[lindex $argv 0] > 4096} {
			puts "ERROR!!!!!!"
			puts "The payload size is too high. It must be less then 4096 charachters."
			puts "Please try again."
			return
		  } else {
        		set opt(pktsize)       [lindex $argv 0]
        		set opt(cbr_period)    [lindex $argv 1]
			    set opt(socket_comm)   [lindex $argv 2]
                set opt(rngstream)     [lindex $argv 3]
		  }
    }
} 

global defaultRNG
for {set k 0} {$k < $opt(rngstream)} {incr k} {
    $defaultRNG next-substream
}


if {$opt(trace_files)} {
    set opt(tracefilename) "./test_uwApplication.tr"
    set opt(tracefile) [open $opt(tracefilename) w]
    set opt(cltracefilename) "./test_uwApplication.cltr"
    set opt(cltracefile) [open $opt(tracefilename) w]
} else {
    set opt(tracefilename) "/dev/null"
    set opt(tracefile) [open $opt(tracefilename) w]
    set opt(cltracefilename) "/dev/null"
    set opt(cltracefile) [open $opt(cltracefilename) w]
}

set channel [new Module/UnderwaterChannel]
set propagation [new MPropagation/Underwater]
set data_mask [new MSpectralMask/Rect]
$data_mask setFreq       $opt(freq)
$data_mask setBandwidth  $opt(bw)

#########################
# Module Configuration  #
#########################
#UW/APPLICATION
Module/UW/APPLICATION set debug_ -1							;# 1= debug activated
Module/UW/APPLICATION set period_ $opt(cbr_period)
Module/UW/APPLICATION set PoissonTraffic_ 0		   ;# 1= use a Poisson process for generate packets
Module/UW/APPLICATION set Payload_size_ $opt(pktsize)
Module/UW/APPLICATION set drop_out_of_order_ 1 		;# 1= drop out of order activate 
Module/UW/APPLICATION set Socket_Port_ 4000
Module/UW/APPLICATION set EXP_ID_ 1


# BPSK              
Module/MPhy/BPSK  set BitRate_          $opt(bitrate)
Module/MPhy/BPSK  set TxPower_          $opt(txpower)

################################
# Procedure(s) to create nodes #
################################
proc createNode { id } {

    global channel propagation data_mask ns app position node udp portnum ipr ipif
    global phy posdb opt rvposx mll mac db_manager
    global node_coordinates
    
    set node($id) [$ns create-M_Node $opt(tracefile) $opt(cltracefile)] 

    set app($id)  [new Module/UW/APPLICATION] 
    set udp($id)  [new Module/UW/UDP]
    set ipr($id)  [new Module/UW/StaticRouting]
    set ipif($id) [new Module/UW/IP]
    set mll($id)  [new Module/UW/MLL] 
    set mac($id)  [new Module/UW/CSMA_ALOHA] 
    set phy($id)  [new Module/MPhy/BPSK]

    $node($id) addModule 7 $app($id)   0  "CBR"
    $node($id) addModule 6 $udp($id)   0  "UDP"
    $node($id) addModule 5 $ipr($id)   0  "IPR"
    $node($id) addModule 4 $ipif($id)  0  "IPF"   
    $node($id) addModule 3 $mll($id)   0  "MLL"
    $node($id) addModule 2 $mac($id)   0  "MAC"
    $node($id) addModule 1 $phy($id)   0  "PHY"

    $node($id) setConnection $app($id)   $udp($id)   0
    $node($id) setConnection $udp($id)   $ipr($id)   0
    $node($id) setConnection $ipr($id)   $ipif($id)  0
    $node($id) setConnection $ipif($id)  $mll($id)   0
    $node($id) setConnection $mll($id)   $mac($id)   0
    $node($id) setConnection $mac($id)   $phy($id)   0
    $node($id) addToChannel  $channel    $phy($id)   0

    set portnum($id) [$udp($id) assignPort $app($id) ]
    if {$id > 254} {
    puts "hostnum > 254!!! exiting"
    exit
    }
    set tmp_ [expr ($id) + 1]
    $ipif($id) addr $tmp_
    
    set position($id) [new "Position/BM"]
    $node($id) addPosition $position($id)
    set posdb($id) [new "PlugIn/PositionDB"]
    $node($id) addPlugin $posdb($id) 20 "PDB"
    $posdb($id) addpos [$ipif($id) addr] $position($id)
    
    set interf_data($id) [new "MInterference/MIV"]
    $interf_data($id) set maxinterval_ $opt(maxinterval_)
    $interf_data($id) set debug_       0

    $phy($id) setPropagation $propagation
    #$cbr($id) setSocketProtocol "TCP"
    $app($id) set node_ID_  $tmp_
    $phy($id) setSpectralMask $data_mask
    $phy($id) setInterference $interf_data($id)
    $mac($id) $opt(ack_mode)
    $mac($id) initialize
}

proc createSink { } {

    global channel propagation smask data_mask ns app_sink position_sink node_sink udp_sink portnum_sink interf_data_sink
    global phy_data_sink posdb_sink opt mll_sink mac_sink ipr_sink ipif_sink bpsk interf_sink

    set node_sink [$ns create-M_Node $opt(tracefile) $opt(cltracefile)]

    for {set cnt 0} {$cnt < $opt(nn)} {incr cnt} {
        set app_sink($cnt)  [new Module/UW/APPLICATION] 
    }
    set udp_sink       [new Module/UW/UDP]
    set ipr_sink       [new Module/UW/StaticRouting]
    set ipif_sink      [new Module/UW/IP]
    set mll_sink       [new Module/UW/MLL] 
    set mac_sink       [new Module/UW/CSMA_ALOHA]
    set phy_data_sink  [new Module/MPhy/BPSK] 

    for { set cnt 0} {$cnt < $opt(nn)} {incr cnt} {
        $node_sink addModule 7 $app_sink($cnt) 0 "CBR"
    }
    $node_sink addModule 6 $udp_sink       0 "UDP"
    $node_sink addModule 5 $ipr_sink       0 "IPR"
    $node_sink addModule 4 $ipif_sink      0 "IPF"   
    $node_sink addModule 3 $mll_sink       0 "MLL"
    $node_sink addModule 2 $mac_sink       0 "MAC"
    $node_sink addModule 1 $phy_data_sink  0 "PHY"

    for { set cnt 0} {$cnt < $opt(nn)} {incr cnt} {
        $node_sink setConnection $app_sink($cnt)  $udp_sink      0   
    }
    $node_sink setConnection $udp_sink  $ipr_sink            0
    $node_sink setConnection $ipr_sink  $ipif_sink           0
    $node_sink setConnection $ipif_sink $mll_sink            0 
    $node_sink setConnection $mll_sink  $mac_sink            0
    $node_sink setConnection $mac_sink  $phy_data_sink       0
    $node_sink addToChannel  $channel   $phy_data_sink       0

    for { set cnt 0} {$cnt < $opt(nn)} {incr cnt} {
        set portnum_sink($cnt) [$udp_sink assignPort $app_sink($cnt)]
        if {$cnt > 252} {
            puts "hostnum > 252!!! exiting"
            exit
        }    
    }
    
    $ipif_sink addr 254

    set position_sink [new "Position/BM"]
    $node_sink addPosition $position_sink
    set posdb_sink [new "PlugIn/PositionDB"]
    $node_sink addPlugin $posdb_sink 20 "PDB"
    $posdb_sink addpos [$ipif_sink addr] $position_sink

    set interf_data_sink [new "MInterference/MIV"]
    $interf_data_sink set maxinterval_ $opt(maxinterval_)
    $interf_data_sink set debug_       0

    $phy_data_sink setSpectralMask $data_mask
    $phy_data_sink setInterference $interf_data_sink
    $phy_data_sink setPropagation $propagation
    for {set cnt 0} {$cnt < $opt(nn)} {incr cnt} {
        #$cbr_sink($cnt) setSocketProtocol "TCP"
        $app_sink($cnt) set node_ID_ 254
    }
    $mac_sink $opt(ack_mode)
    $mac_sink initialize
}

#################
# Node Creation #
#################
# Create here all the nodes you want to network together
for {set id 0} {$id < $opt(nn)} {incr id}  {
    createNode $id
}
createSink

################################
# Inter-node module connection #
################################
proc connectNodes {id1} {
    global ipif ipr portnum app app_sink ipif_sink portnum_sink ipr_sink

    $app($id1) set destAddr_ [$ipif_sink addr]
    $app($id1) set destPort_ $portnum_sink($id1)
    $app_sink($id1) set destAddr_ [$ipif($id1) addr]
    $app_sink($id1) set destPort_ $portnum($id1)
}

# Setup flows
for {set id1 0} {$id1 < $opt(nn)} {incr id1}  {
    connectNodes $id1
}

# Fill ARP tables
for {set id1 0} {$id1 < $opt(nn)} {incr id1}  {
    for {set id2 0} {$id2 < $opt(nn)} {incr id2}  {
      $mll($id1) addentry [$ipif($id2) addr] [$mac($id2) addr]
    }   
    $mll($id1) addentry [$ipif_sink addr] [ $mac_sink addr]
    $mll_sink addentry [$ipif($id1) addr] [ $mac($id1) addr]
}

# Setup positions
$position(0) setX_ 0
$position(0) setY_ 0
$position(0) setZ_ -1000

#$position(1) setX_ 500
#$position(1) setY_ 500
#$position(1) setZ_ -1000

$position_sink setX_ 1000
$position_sink setY_ 1000
$position_sink setZ_ -1000

# Setup routing table
$ipr(0) addRoute [$ipif_sink addr] [$ipif_sink addr];#[$ipif(1) addr]
#$ipr(1) addRoute [$ipif_sink addr] [$ipif_sink addr]

#$ipr(0) defaultGateway [$ipif(1) addr]
#$ipr(1) defaultGateway [$ipif_sink addr]

#####################
# Start/Stop Timers #
#####################
# Set here the timers to start and/or stop modules (optional)
# e.g., 


###################
# Final Procedure #
###################
# Define here the procedure to call at the end of the simulation
proc finish {} {
    global ns opt
    global mac propagation app_sink mac_sink phy_data phy_data_sink channel db_manager propagation
    global node_coordinates
    global ipr_sink ipr ipif udp app phy phy_data_sink
    global node_stats tmp_node_stats sink_stats tmp_sink_stats

    puts "---------------------------------------------------------------------"
    puts "Simulation summary"
    puts "number of nodes  : $opt(nn)"
    puts "packet size      : $opt(pktsize) byte"
    puts "app period       : $opt(cbr_period) s"
    puts "number of nodes  : $opt(nn)"
    puts "simulation length: $opt(txduration) s"
    puts "tx frequency     : $opt(freq) Hz"
    puts "tx bandwidth     : $opt(bw) Hz"
    puts "bitrate          : $opt(bitrate) bps"
    puts "---------------------------------------------------------------------"

    set sum_cbr_throughput     0
    set sum_per                0
    set sum_cbr_sent_pkts      0.0
    set sum_cbr_rcv_pkts       0.0    
    set sum_cbr_queue_pkts		 0.0

    for {set i 0} {$i < $opt(nn)} {incr i}  {
        set cbr_throughput           [$app_sink($i) getthr]
        set cbr_sent_pkts        [$app($i) getsentpkts]
        
        set cbr_rcv_pkts           [$app_sink($i) getrecvpkts]
		  if { $opt(socket_comm) == 1 } {	
        		set cbr_queue_pkts			[$app($i) getrecvpktsqueue]
		  }
 		  set sum_cbr_throughput [expr $sum_cbr_throughput + $cbr_throughput]
        set sum_cbr_sent_pkts  [expr $sum_cbr_sent_pkts + $cbr_sent_pkts]
        set sum_cbr_rcv_pkts   [expr $sum_cbr_rcv_pkts + $cbr_rcv_pkts]
		  if { $opt(socket_comm) == 1 } {
        		set sum_cbr_queue_pkts [expr $sum_cbr_queue_pkts + $cbr_queue_pkts]
		  }
    }
        
    puts "Mean Throughput          : [expr ($sum_cbr_throughput/($opt(nn)))]"

	puts "Sent Packets             : $sum_cbr_sent_pkts"
	puts "Received Packets         : $sum_cbr_rcv_pkts"
    puts "Packet Delivery Ratio    : [expr $sum_cbr_rcv_pkts / $sum_cbr_sent_pkts * 100]"
  
    $ns flush-trace
    close $opt(tracefile)
}

###################
# start simulation
###################
for {set id1 0} {$id1 < $opt(nn)} {incr id1}  {
    $ns at $opt(starttime)    "$app($id1) start"
    $ns at $opt(stoptime)     "$app($id1) stop"
}

$ns at [expr $opt(stoptime) + 30.0] "finish; $ns halt"
$ns run
