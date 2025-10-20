#!/bin/bash

# Securily Security Headers Scanner - Example Scan Script
# This script provides examples of how to use the scanner

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Optional: Set API key for AI insights
API_KEY="$1"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Securily Security Headers Scanner - Example Scans            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Example 1: Basic scan
echo -e "${YELLOW}Example 1: Basic Web Application Scan${NC}"
echo "Target: https://securily.com"
echo "Command: ./securily-headers.sh -u https://securily.com"
echo ""
read -p "Press Enter to run this scan (or Ctrl+C to skip)..."
./securily-headers.sh -u https://securily.com
echo ""
echo -e "${GREEN}✓ Results saved to results.json${NC}"
echo ""
sleep 2

# Example 2: Verbose scan with detailed output
echo -e "${YELLOW}Example 2: Verbose Scan with Detailed Output${NC}"
echo "Target: https://example.com"
echo "Command: ./securily-headers.sh -u https://example.com -v"
echo ""
read -p "Press Enter to run this scan (or Ctrl+C to skip)..."
./securily-headers.sh -u https://example.com -v
echo ""
echo -e "${GREEN}✓ Results saved to results.json${NC}"
echo ""
sleep 2

# Example 3: Your own website
echo -e "${YELLOW}Example 3: Scan Your Own Website${NC}"
echo ""
read -p "Enter your website URL (or press Enter to skip): " USER_URL
if [ ! -z "$USER_URL" ]; then
    if [ ! -z "$API_KEY" ]; then
        echo "Command: ./securily-headers.sh -u $USER_URL -ai $API_KEY -v"
        ./securily-headers.sh -u "$USER_URL" -ai "$API_KEY" -v
        echo ""
        echo -e "${GREEN}✓ Results saved to results.json with AI insights${NC}"
    else
        echo "Command: ./securily-headers.sh -u $USER_URL -v"
        ./securily-headers.sh -u "$USER_URL" -v
        echo ""
        echo -e "${GREEN}✓ Results saved to results.json${NC}"
    fi
    echo ""
else
    echo "Skipped."
    echo ""
fi

# Example 4: Pretty print results
echo -e "${YELLOW}Example 4: View Formatted Results${NC}"
echo "Command: cat results.json | python3 -m json.tool"
echo ""
read -p "Press Enter to view results (or Ctrl+C to skip)..."
cat results.json | python3 -m json.tool | head -50
echo ""
echo -e "${BLUE}... (showing first 50 lines)${NC}"
echo ""

# Summary
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Example Scans Complete!                                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Next Steps:"
echo "  1. Review results.json for detailed findings"
echo "  2. Check README.md for all supported headers"
echo "  3. Scan your own website for security analysis"
echo ""
echo "Additional Options:"
echo "  -a  Add authorization token for API scans"
echo "  -v  Verbose output (detailed information)"
echo "  -ai Add Gemini API key for AI insights"
echo ""
echo "Documentation:"
echo "  README.md                   - Complete guide and header reference"
echo "  configuration.json          - All header definitions"
echo "  example_scan.sh             - This example script"
echo ""

