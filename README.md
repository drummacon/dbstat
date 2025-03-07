## dbstat (macOS 13.0+)
A simple forensics dashboard for monitoring real-time metrics on macOS.
This project is provided as a free resource, and community contributions are always welcome. New to Git? First-time committers are encouraged.

### Requirements:
- **Node.js**: 16+  
- **macOS**: 11.0+ (Big Sur or later)
- **Browser**: ✅ Safari / ✅ Firefox (Compatible with any modern browser)

### Real-time metrics supported (more will be added):
- Network
- Port watcher
- Running processes
- Storage analytics  
- Logged-in sessions
- And many more!

### Additional features:
- Dark/light themes
- GitHub integration
- OpenAI API support (optional)

### Screenshots

<p align="center">
  <img src="./assets/images/app-screenshot-light.png" alt="Light Theme Screenshot" width="700">
  <br>
  <span style="display: block; text-align: center; font-size: 90%; color: #666;">Light Theme</span>
</p>

<p align="center">
  <img src="./assets/images/app-screenshot-dark.png" alt="Dark Theme Screenshot" width="700">
  <br>
  <span style="display: block; text-align: center; font-size: 90%; color: #666;">Dark Theme</span>
</p>

### Dependencies:
| Package | Version |
|---------|---------|
| express | `4.17.1` |
| socket.io | `4.8.1` |
| systeminformation | `5.11.9` |
| jsonwebtoken | `9.0.2` |
| helmet | `8.0.0` |
| dotenv | `16.0.0` |

### Installation

1. **Clone the repo and navigate to the project directory**
    ```bash
    git clone https://github.com/cgtwig/dbstat
    cd dbstat
    ```

2. **Install required dependencies**
    ```bash
    npm install
    ```

3. **Configure environment variables**

    ```bash
    # Server configuration
    PORT=3000
    HOST=127.0.0.1
    CORS_ORIGIN=http://127.0.0.1:3000
    
    # (REQUIRED) Replace `insert-token-here` using the terminal command provided in README.md
    JWT_SECRET=insert-token-here
    
    # (OPTIONAL) Security command generation test feature
    # OPENAI_API_KEY=your-api-key
    ```

4. **Rename `.env-example` to `.env` and replace `JWT_SECRET` value using the command below**
    ```bash
    node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
    ```
    This generates a cryptographically secure JWT token via the terminal.

5. **OpenAI API setup (OPTIONAL)**
    This is an experimental feature - The OpenAI API is utilized for generating example terminal commands to assist during forensic workflows. 

    **Configuration:**
    - Locate the commented line in your `.env` file: `# OPENAI_API_KEY=your-api-key`
    - Remove the `#` comment prefix
    - Replace `your-api-key` with your valid OpenAI API key
    
    **Note:** When enabled, API calls are made using the `gpt-4o-mini` model (approximate cost < $0.01 per request). Each 'regenerate' action triggers a new API request.

6. **Launch the application**
    ```bash
    npm start
    ```
    The server will initialize and become accessible at `http://localhost:3000` via your browser.  

    If you encounter any issues or would like to request additional functionality, please submit details through the GitHub issues section.

### License
This project is licensed under the MIT License and is **open source**. Contributions are welcome!

#macOS #forensics #cybersecurity #infosec #incidentresponse #endpointmonitoring #systemmonitoring #openai #aiintegration #techdashboard #devtools #webdevelopment #nodejs #real-timeanalytics #networksecurity #servermonitoring #securitytools #opensource #privacy #datatracking #cloudsecurity #ITsecurity #systemadministration #monitoringtools #datavisualization #webapp #networkmanagement #aiinsecurity
