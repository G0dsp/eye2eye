# Eye2Eye

![Eye2Eye](https://github.com/G0dsp/eye2eye/assets/88639130/3fea32d0-e2be-4c7c-8adb-5e1c171539dc)

Eye2Eye is a sophisticated Python-based cyber intelligence tool designed for global domains. This tool is meticulously crafted to extract essential insights about specified domains.

![Eye2Eye](https://github.com/G0dsp/eye2eye/assets/88639130/7089fd8e-2aab-442b-a3b3-71a4b9db5276)

## Key Features

1. **Reverse IP Lookup:** Provides a comprehensive list of domains sharing the same IP address as the input domain, potentially revealing connections between different domains.

2. **WHOIS Lookup:** Retrieves exhaustive details about domain registration, including owner information, contact details, and registrar specifics.

3. **Port Scanning:** Conducts a thorough scan of ports on the IP address associated with the domain, identifying open ports susceptible to potential attacks.

4. **Hackertarget Tools:** Leverages various Hackertarget tools for executing cyber intelligence operations, including MTR Traceroute, Ping, DNS Lookup, Reverse DNS Lookup, IP Geolocation, Reverse IP Lookup, Fetching HTTP Headers, Page Link Retrieval, and AS Lookup.

## Results Saving

Eye2Eye now conveniently saves the results of these operations into a text file, streamlining the review and analysis of the collected information.

## Usage

1. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

2. Set up the necessary API keys by creating a `.env` file with the following content:

    ```env
    HACKERTARGET_API_KEY=your_hackertarget_api_key
    VIRUSTOTAL_API_KEY=your_virustotal_api_key
    ```

3. Run the Eye2Eye tool:

    ```bash
    python eye2eye.py
    ```

**Note:** Ensure the use of the [Hackertarget API](https://hackertarget.com/) and the [VirusTotal API](https://www.virustotal.com/) for an enhanced working experience.

## Contribution

Contributions to the project are welcome! Feel free to contribute and enhance its capabilities. Your efforts are highly appreciated.

Happy hacking!