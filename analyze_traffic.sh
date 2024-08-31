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


#___________________________Functions______________________________
function printIntro () {
    echo ""
    echo "__________😀*welcome to traffic analyzer*😀__________"
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

function analyzePackets () {
    tshark -r "$1"  -T fields -e frame.number -e frame.protocols -e ip.src -e ip.dst -e ip.proto -e frame.len -e frame.time -E header=y -E separator=, -E quote=d |
    while IFS=, read -r frame_number frame_protocols ip_src ip_dst ip_proto frame_len frame_time
    do
        if [ "$frame_number" == "frame.number" ]; then
            continue
        fi
        printPacket "$frame_number" "$frame_protocols" "$ip_src" "$ip_dst" "$ip_proto" "$frame_len" "$frame_time"
        printLine
        sleep 0.3
    done
}

function Timer () {
    for i in {4..0}; do
        echo -ne " Analyzing pcap file 🕐 : $i\r"
        sleep 1
    done
    echo ""
}

function printTableHeader () {
    printf "| %-25s | %-20s |\n" "Category" "Count"
    echo "----------------------------------------------------"
}

function printTableData () {
    printf "| %-25s | %-20s |\n" "$1" "$2"
    echo "----------------------------------------------------"
    sleep 0.3
}


#______________________________________ MAIN ________________________________________________________

function main () {
    printIntro
    read -r -p "please,enter your pcap file path 📂 : " PCAP_FILE
    if [ ! -f "$PCAP_FILE" ]; then
        echo ""
        echo "Error: The file does not exist or not found ❌"
        exit 1
    fi
    echo ""
    echo "Everything is well: ✅"
    echo ""
    Timer 
    echo ""
    # Extract total packet count
    TOTAL_PACKETS=$(tshark -r "$PCAP_FILE" -T fields -e frame.number | wc -l)
    # Extract unique list of protocols
    PROTOCOL_LIST=$(tshark -r "$PCAP_FILE" -T fields -e _ws.col.Protocol | sort | uniq | tr '\n' ' ')
    # Count packets per protocol
    PACKETS_PER_PROTOCOL=$(tshark -r "$PCAP_FILE" -T fields -e _ws.col.Protocol | sort | uniq -c | sort -nr | awk '{printf "%s: %s\n", $2, $1}')
    printHeaders
    printLine
    analyzePackets "$PCAP_FILE"
    echo ""
    echo ""
    printLine
    # Print total packet count
    echo "Total packet count: $TOTAL_PACKETS"
    printLine
    # Print list of all protocols
    echo "List of all protocols: $PROTOCOL_LIST"
    printLine
    # Print packet count per protocol
    echo ""
    echo "Packet count per protocol 📊 :"
    echo "----------------------------------------------------"
    if [ -n "$PACKETS_PER_PROTOCOL" ]; then
        printTableHeader
        while IFS=: read -r protocol count; do
            protocol=$(echo "$protocol" | xargs)  # Trim leading/trailing whitespace
            count=$(echo "$count" | xargs)  # Trim leading/trailing whitespace
            printTableData "$protocol" "$count"
        done <<< "$PACKETS_PER_PROTOCOL"
    else
        echo "| No packet count per protocol found           |                      |"
        echo "----------------------------------------------------"
    fi
    echo ""
    echo -e " Analysis complete! \U1F3C1"
    echo -e " Check the summary above for details. \U1F50D"
    echo ""
}



#______________________________________________

main



