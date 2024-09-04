#!/usr/bin/bash

#_____________________________Describtion___________________________#
#
# Script Name: analyze_traffic.sh
# Usage      : ./analyze_traffic.sh
#
# Auther     : Ahmed Hussein
# Date       : 30/8/2024
#
#___________________________________________________________________#


#________________________CONFIGURATIONS____________________________

CONFIG_FILE="./config.conf"
if [ -f "$CONFIG_FILE" ]; 
then
    source "$CONFIG_FILE"
else
    echo "configuration file not found !"
    exit 1
fi


#___________________________Functions______________________________

function checkFileStatus () {
    
    if [ ! -f "$1" ]; then
        echo ""
        echo "Error: The file does not exist or not found ❌"
        exit 1
    fi
    echo ""
    echo "Everything is well: ✅"
    echo ""
}

function printIntro () {
    echo ""
    echo "__________😀*welcome to traffic analyzer*😀__________"
    echo ""

}

function Timer () {
    for i in {4..0}; do
        echo -ne " Analyzing pcap file 🕐 : $i\r"
        sleep 1
    done
    echo ""
    echo ""
}

function printLine () {
    echo "------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
}

function printPacket () {
    printf "| %-10s | %-40s | %-17s | %-17s | %-10s | %-15s | %-35s |\n" "$1" "$2" "$3" "$4" "$5" "$6" "$7"
}

function printHeaders () {
    headers=("Frame_Num" "Protocols" "Source_IP" "Destination_IP" "Protocol" "Frame_Len" "Timestamp")
    printLine
    printf "| %-10s | %-40s | %-17s | %-17s | %-10s | %-15s | %-37s |\n" "${headers[@]}"
}

function printTableHeader () {
    echo "----------------------------------------------------"
    printf "| %-25s | %-20s |\n" "Category" "Count"
    echo "----------------------------------------------------"
}

function printTableData () {
    printf "| %-25s | %-20s |\n" "$1" "$2"
    echo "----------------------------------------------------"
    sleep 0.1
}

function printTop5Header () {
    echo "-------------------------------------------------------------------"
    printf "| %-40s | %-20s |\n" "IP" "Count"
    echo "-------------------------------------------------------------------"
}

function printTop5Data () {
    if [ -n "$1" ]; then
        printf "| %-40s | %-20s |\n" "$1" "$2"
        echo "-------------------------------------------------------------------"
        sleep 0.1
    fi
}

function printTop5 () {
    if [ -n "$1" ]; then
        printTop5Header
        while read -r count ip; do
            printTop5Data "$ip" "$count"
        done <<< "$1"
    fi
    echo ""
}

function printTotalPackets () {
    echo ""
    printLine
    # Print total packet count
    echo "Total packet count: $1"
}

function printProtcolList () {
    printLine
    # Print list of all protocols
    echo "List of all protocols: $1"
    printLine
}

function printPacketPerProtocol () {
    # Print packet count per protocol
    echo ""
    echo "Packet count per protocol 📊 :"
    echo ""
    if [ -n "$1" ]; then
        printTableHeader
        while IFS=: read -r protocol count; do
            protocol=$(echo "$protocol" | xargs)  # Trim leading/trailing whitespace
            count=$(echo "$count" | xargs)  # Trim leading/trailing whitespace
            printTableData "$protocol" "$count"
        done <<< "$1"
    else
        echo "| No packet count per protocol found           |                      |"
        echo "----------------------------------------------------"
    fi
    echo ""
}

function analyzePackets () {
    printHeaders
    printLine
    tshark -r "$1" -Y "$FILTERED_PROTOCOLS" -T fields -e frame.number -e frame.protocols -e ip.src -e ip.dst -e ip.proto -e frame.len -e frame.time -E header=y -E separator=, -E quote=d |
    while IFS=, read -r frame_number frame_protocols ip_src ip_dst ip_proto frame_len frame_time
    do
        if [ "$frame_number" == "frame.number" ]; then
            continue
        fi
        printPacket "$frame_number" "$frame_protocols" "$ip_src" "$ip_dst" "$ip_proto" "$frame_len" "$frame_time"
        printLine
        sleep 0.3
    done
    echo ""
    # Extract total packet count
    TOTAL_PACKETS=$(tshark -r "$PCAP_FILE" -T fields -e frame.number | wc -l)
    # Extract unique list of protocols
    PROTOCOL_LIST=$(tshark -r "$PCAP_FILE" -T fields -e _ws.col.Protocol | sort | uniq | tr '\n' ' ')
    # Count packets per protocol
    PACKETS_PER_PROTOCOL=$(tshark -r "$PCAP_FILE" -T fields -e _ws.col.Protocol | sort | uniq -c | sort -nr | awk '{printf "%s: %s\n", $2, $1}')
    #Top 5 source IP
    TOP_5_SOURCE=$(tshark -r "$PCAP_FILE" -T fields -e ip.src | sort | uniq -c | sort -nr | head -5)
    #Top 5 destination IP
    TOP_5_DESTINATION=$(tshark -r "$PCAP_FILE" -T fields -e ip.dst | sort | uniq -c | sort -nr | head -5)
    printTotalPackets "$TOTAL_PACKETS"
    printProtcolList  "$PROTOCOL_LIST"
    printPacketPerProtocol "$PACKETS_PER_PROTOCOL"
    echo "TOP_5_SOURCE :"
    printTop5 "$TOP_5_SOURCE"
    echo "TOP_5_DESTINATION :"
    printTop5 "$TOP_5_DESTINATION"

}

#______________________________________ MAIN ________________________________________________________

function main () {
    #Redirect the output to a log file 
    exec > >(tee -a "$LOG_FILE") 2>&1
    printIntro
    read -r -p "please,enter your pcap file path 📂 : " PCAP_FILE
    checkFileStatus "$PCAP_FILE"
    Timer 
    analyzePackets "$PCAP_FILE"
    echo -e " Analysis complete! \U1F3C1"
    echo -e " Check the summary above for details. \U1F50D"
    echo ""
}



#______________________________________________

main



