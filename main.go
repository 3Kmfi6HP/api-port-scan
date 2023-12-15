package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type ScanResult struct {
	Success int    `json:"success"`
	Msg     Msg    `json:"msg"`
	IP      string `json:"ip"`
	Region  string `json:"region"`
}

type Msg struct {
	Status string `json:"status"`
	IP     string `json:"ip"`
	Port   string `json:"port"`
}

func main() {
	fileName := "ip.txt"
	ports := []string{"80", "443", "8080", "8880", "2052", "2082", "2086", "2095", "2053", "2083", "2087", "2096", "8443"}

	// Perform API scan on given IP addresses and ports
	results := apiscan(fileName, ports)

	outputFileName := "scan_results.txt"
	err := writeScanResultsToFile(results, outputFileName)
	if err != nil {
		fmt.Println("Failed to write scan results to file:", err)
		return
	}

	fmt.Println("Scan results written to", outputFileName)
}

func apiscan(fileName string, ports []string) []ScanResult {
	var wg sync.WaitGroup
	results := make([]ScanResult, 0)

	// Read IP addresses from file
	IPs := readIPsFromFile(fileName)
	if len(IPs) == 0 {
		fmt.Println("No IP addresses found in the file.")
		return results
	}

	for _, ip := range IPs {
		// Convert CIDR notation to individual IP addresses
		cidrIPs, err := ConvertCIDRToIPs(ip)
		if err != nil {
			fmt.Printf("Failed to convert CIDR to IPs for IP: %s\n", ip)
			continue
		}

		for _, cidrIP := range cidrIPs {
			for _, port := range ports {
				wg.Add(1)
				go func(ip, port string) {
					defer wg.Done()

					// Construct URL for API call
					url := fmt.Sprintf("http://duankou.wlphp.com/api.php?i=%s&p=%s", ip, port)

					// Perform HTTP GET request to the API
					resp, err := http.Get(url)
					if err != nil {
						// Handle error during HTTP request
						return
					}
					defer resp.Body.Close()

					// Read response body
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						// Handle error while reading response body
						return
					}

					// Extract JSON response from body using regex
					jsonRegex := regexp.MustCompile(`{.*}`)
					jsonResp := jsonRegex.Find(body)
					// fmt.Print(jsonResp)

					// Parse JSON response
					var result ScanResult
					err = json.Unmarshal(jsonResp, &result)
					if err != nil {
						// Handle JSON parsing error
						// fmt.Printf("Failed to parse JSON response for IP: %s, Port: %s Err:%s\n", ip, port, err)
						return
					}
					fmt.Println("Request Body:", string(jsonResp))

					// Append successful scan results to the results slice
					if result.Success == 1 && result.Msg.Status == "Openning" {
						// Lock the file before writing to avoid race condition
						writeToFile(fmt.Sprintf("IP: %s, Port: %s, Status: %s\n", result.IP, result.Msg.Port, result.Msg.Status), "live_scan_results.txt")
					}
				}(cidrIP, port)
			}
		}
	}

	wg.Wait()

	return results
}

func writeToFile(line, fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Failed to open file:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(line)
	if err != nil {
		fmt.Println("Failed to write to file:", err)
		return
	}

	writer.Flush()
}

func readIPsFromFile(fileName string) []string {
	ips := make([]string, 0)

	// Open file for reading
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println("Failed to open file.")
		return ips
	}
	defer file.Close()

	// Read IP addresses line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ips = append(ips, ip)
		}
	}

	// Check for any errors while reading file
	if err := scanner.Err(); err != nil {
		fmt.Println("Failed to read file.")
		return ips
	}

	return ips
}

func ConvertCIDRToIPs(cidr string) ([]string, error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Invalid CIDR format: %s", cidr)
	}

	ips := make([]string, 0)
	ip := parts[0]
	prefix, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("Invalid CIDR format: %s", cidr)
	}

	cidrIP := net.ParseIP(ip)
	if cidrIP == nil {
		return nil, fmt.Errorf("Invalid IP address: %s", ip)
	}

	ipNet := &net.IPNet{IP: cidrIP, Mask: net.CIDRMask(prefix, 32)}
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func writeScanResultsToFile(results []ScanResult, fileName string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, result := range results {
		if result.Msg.Status == "Openning" {
			line := fmt.Sprintf("IP: %s, Port: %s, Status: %s\n", result.IP, result.Msg.Port, result.Msg.Status)
			_, err := writer.WriteString(line)
			if err != nil {
				return err
			}
		}
	}

	writer.Flush()
	return nil
}
