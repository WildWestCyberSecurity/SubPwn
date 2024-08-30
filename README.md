# 🎯 SubPwn: Advanced Subdomain Enumeration and VHost Brute-Forcing Tool 🕵️‍♂️

![SubPwn Logo](https://raw.githubusercontent.com/WildWestCyberSecurity/SubPwn/main/SubPwn_Logo.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.x-brightgreen.svg)](https://www.python.org/)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)
![Stars](https://img.shields.io/github/stars/WildWestCyberSecurity/SubPwn?style=social)

🚀 **SubPwn** is an all-in-one subdomain enumeration, VHost brute-forcing, and active subdomain verification tool for penetration testers and cybersecurity professionals. Use it to uncover hidden subdomains and virtual hosts, enhancing your security assessments with a comprehensive, multi-phase approach.

---

## ✨ Features

- 🔍 **Passive Subdomain Enumeration**: Leverage tools like Sublist3r, Subfinder, and the SecurityTrails API to gather subdomains.
- 💣 **Active Subdomain Brute-Forcing**: Use wordlists to identify subdomains missed by passive methods.
- 🌐 **VHost Brute-Forcing**: Discover virtual hosts sharing the same IP using DNS resolution.
- 🌍 **DNS Zone Transfer Attacks**: Attempt DNS zone transfers to uncover subdomains exposed by misconfigurations.
- ✅ **Subdomain Verification**: Check HTTP/HTTPS status codes to find active endpoints.
- 📊 **Detailed Logging and Reporting**: Generate comprehensive logs and output files for easy analysis.
- 🔄 **Resume Functionality**: Ability to resume interrupted scans for both DNS enumeration and VHost brute-forcing.
- 🚀 **Fast Mode**: Option to run all tools with maximum speed for quicker results.
- 🎨 **Colorized Output**: Improved readability with color-coded console output.

## 📸 Screenshot of `-h` Output

![Help Output](https://raw.githubusercontent.com/WildWestCyberSecurity/SubPwn/main/SubPwn_Screenshot2.png) <!-- Replace with the actual path to your screenshot after uploading -->

## ⚡ Installation

1. **Clone the Repository:**
   `
   git clone https://github.com/WildWestCyberSecurity/SubPwn.git
   cd SubPwn
   `

2. **Install Dependencies:**
   `
   pip install -r requirements.txt
   `

3. **Ensure Required Tools are Installed:**
   SubPwn relies on external tools like Sublist3r, Subfinder, Gobuster, lolcat, and FFUF. Ensure these are installed and accessible in your system's PATH.

4. **Ensure chmod execute bit set +x if not run with python3 subpwn.py :)**
   chmod +x subpwn.py

## 🚀 Usage

Run SubPwn with the desired options:

`
./subpwn.py -d example.com -w wordlist.txt -o output_dir
`

### 💡 Example Commands

- **Single Domain Enumeration:**
  ```
  ./subpwn.py -d example.com -w wordlist.txt -o output_dir
  ```

- **Multiple Domains from a List:**
  ```
  ./subpwn.py -dL domains.txt -w wordlist.txt -o output_dir
  ```

- **Fast Mode with Selected Phases:**
  ```
  ./subpwn.py -d example.com -o output_dir -FF --skip-p2 --skip-p3
  ```

- **Custom Save Interval for DNS Enumeration:**
  ```
  ./subpwn.py -d example.com -w wordlist.txt -o output_dir --save-interval 100
  ```

## ⚙️ Options

SubPwn supports a variety of command-line arguments. To view all options, run:

`
./subpwn.py -h
`

Key options include:
- `-FF, --fast`: Run all tools with maximum speed
- `--save-interval`: Set the interval for saving progress in DNS enumeration
- `--skip-p1` to `--skip-p5`: Skip specific phases of the enumeration process
- `--max-workers`: Set the maximum number of worker threads for subdomain verification and vhost scanning

## 🤝 Contributing

Contributions are welcome! Please fork the repository, create a new branch for your changes, and submit a pull request.  
Don’t forget to ⭐ star the repo if you find it useful!

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## 📧 Contact

For questions or suggestions, feel free to open an issue or reach out to [James Doll](mailto:support@wildwestcyber.com).

---

### 💬 Connect with Us

[![Twitter](https://img.shields.io/twitter/follow/WildWestCyber?style=social)](https://twitter.com/WildWestCyber)  
[![GitHub followers](https://img.shields.io/github/followers/WildWestCyberSecurity?style=social)](https://github.com/WildWestCyberSecurity)
