# OAuth 2.0 Implementation in Go

This project is a simple implementation of an OAuth 2.0 Authorization Server in Go, specifically demonstrating the **Authorization Code Flow with PKCE**, which is the recommended standard for modern applications (Web Apps, SPAs, Mobile).

## 🔄 Detailed Authorization Flow (PKCE)

The following flow represents the secure interaction between the **Resource Owner** (User), the **Client** (Print Magic), the **Authorization Server**, and the **Resource Server** (Snap Store).

```
Resource Owner           Client                Auth Server           Resource Server
   (User)             (Print Magic)           (Google/Auth0)          (Snap Store)
     |                      |                       |                       |
     |--(1) "Fetch Photos"->|                       |                       |
     |   (Click Login)      |                       |                       |
     |                      |                       |                       |
     |                      |--(2) Auhtorization--->|                       |
     |                      |      Request +        |                       |
     |                      |      Challenge        |                       |
     |                      |                       |                       |
     |<-(3) Auth Screen ----|-----------------------|                       |
     |                      |                       |                       |
     |--(4) User Consents ->|---------------------->|                       |
     |                      |                       |                       |
     |                      |<-(5) Auth Code -------|                       |
     |                      |                       |                       |
     |                      |--(6) Auth Code + ---->|                       |
     |                      |      Verifier         |                       |
     |                      |  (Secure Channel)     |                       |
     |                      |                       |                       |
     |                      |<-(7) Access Token ----|                       |
     |                      |                       |                       |
     |                      |--(8) Access Token --------------------------->|
     |                      |                       |                       |
     |                      |<-(9) Protected Data (Photos) -----------------|
```

### 🧩 The 4 Actors

1.  **Resource Owner**: The **User** (You) who owns the photos.
2.  **Client Application**: **"Print Magic"**. This is the app you are using (e.g., your Browser or Mobile App). It initiates the flow.
3.  **Authorization Server**: The server that checks your password and issues the **Token** (handled by `/authorize` and `/token` in our Go code).
4.  **Resource Server**: **"Snap Store"**. The API that holds your photos (handled by `/userinfo` in our Go code).

### 🛡️ Why PKCE is Secure (Step 6)
In Step 2, "Print Magic" sends a hashed **Challenge** (Lock).
In Step 6, "Print Magic" sends the **Code** AND the **Verifier** (Key).
The Server checks if the Key matches the Lock before giving the Token. Since the Verifier is sent over a direct, secure HTTPS channel, it is safe!

## 🚀 Getting Started

### Prerequisites
- Go installed on your machine.

### Running the Server

1.  Clone this repository.
2.  Run the main file:
    ```bash
    go run main.go
    ```
3.  The server will start at `http://localhost:8080`.

## 🧪 Testing the Flow

1.  **Start the flow**: Open your browser and go to the authorization URL (check the terminal output or the guide below).
2.  **Callback**: You will be redirected to a callback URL with a `code`.
3.  **Exchange Token**: Use cURL to exchange the `code` for an access token.
4.  **Access Data**: Use the token to access `/userinfo`.

For detailed step-by-step instructions and specific cURL commands, valid credentials, and PKCE strings, please refer to the main guide:

👉 **[Read the Full OAuth 2.0 Guide](./OAUTH2_GUIDE.md)** for detailed concepts and copy-paste commands.

## 📚 Core Concepts

- **Authorization Code Flow**: Safe way to get tokens without exposing credentials in the browser/client.
- **PKCE (Proof Key for Code Exchange)**: Security extension to prevent interception of the authorization code.
- **State Parameter**: Prevents CSRF attacks.

