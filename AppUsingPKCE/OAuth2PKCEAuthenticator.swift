//
//  OAuth2PKCEAuthenticator.swift
//  AppUsingPKCE
//
//  Created by Eidinger, Marco on 12/16/21.
//

import AuthenticationServices
import CommonCrypto
import Foundation

public enum OAuth2PKCEAuthenticatorError: LocalizedError {
    case authRequestFailed(Error)
    case authorizeResponseNoUrl
    case authorizeResponseNoCode
    case tokenRequestFailed(Error)
    case tokenResponseNoData
    case tokenResponseInvalidData(String)

    var localizedDescription: String {
        switch self {
        case .authRequestFailed(let error):
            return "authorization request failed: \(error.localizedDescription)"
        case .authorizeResponseNoUrl:
            return "authorization response does not include a url"
        case .authorizeResponseNoCode:
            return "authorization response does not include a code"
        case .tokenRequestFailed(let error):
            return "token request failed: \(error.localizedDescription)"
        case .tokenResponseNoData:
            return "no data received as part of token response"
        case .tokenResponseInvalidData(let reason):
            return "invalid data received as part of token response: \(reason)"
        }
    }
}

public struct OAuth2PKCEParameters {
    public var authorizeUrl: String
    public var tokenUrl: String
    public var clientId: String
    public var redirectUri: String
    public var callbackURLScheme: String
}


public struct AccessTokenResponse: Codable {
    public var access_token: String
    public var expires_in: Int
}

public class OAuth2PKCEAuthenticator: NSObject {

    public func authenticate(parameters: OAuth2PKCEParameters, completion: @escaping (Result<AccessTokenResponse, OAuth2PKCEAuthenticatorError>) -> Void) {
        // 1. creates a cryptographically-random code_verifier
        let code_verifier = self.createCodeVerifier()
        // 2. and from this generates a code_challenge
        let code_challenge = self.codeChallenge(for: code_verifier)
        // 3. redirects the user to the authorization server along with the code_challenge
        let authenticationSession = ASWebAuthenticationSession(
            url: URL(string: "\(parameters.authorizeUrl)?response_type=code&code_challenge=\(code_challenge)&code_challenge_method=S256&client_id=\(parameters.clientId)&redirect_uri=\(parameters.redirectUri)")!,
            callbackURLScheme: parameters.callbackURLScheme) { optionalUrl, optionalError in
                // authorization server stores the code_challenge and redirects the user back to the application with an authorization code, which is good for one use
                guard optionalError == nil else { completion(.failure(.authRequestFailed(optionalError!))); return }
                guard let url = optionalUrl else { completion(.failure(.authorizeResponseNoUrl)); return }
                guard let code = url.getQueryStringParameter("code") else { completion(.failure(.authorizeResponseNoCode)); return }
                // 4. sends this code and the code_verifier (created in step 2) to the authorization server (token endpoint)
                self.getAccessToken(authCode: code, codeVerifier: code_verifier, parameters: parameters, completion: completion)
            }
        authenticationSession.presentationContextProvider = self
        authenticationSession.start()
    }

    private func createCodeVerifier() -> String {
        var buffer = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
        return Data(bytes: buffer)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            .trimmingCharacters(in: .whitespaces)
    }

    private func codeChallenge(for verifier: String) -> String {
        // Dependency: Apple Common Crypto library
        // http://opensource.apple.com//source/CommonCrypto
        guard let data = verifier.data(using: .utf8) else { fatalError() }
        var buffer = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &buffer)
        }
        let hash = Data(bytes: buffer)
        return hash.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            .trimmingCharacters(in: .whitespaces)
    }

    private func getAccessToken(authCode: String, codeVerifier: String, parameters: OAuth2PKCEParameters, completion: @escaping (Result<AccessTokenResponse, OAuth2PKCEAuthenticatorError>) -> Void) {

        let request = URLRequest.createTokenRequest(
            parameters: parameters,
            code: authCode,
            codeVerifier: codeVerifier)

        let session = URLSession.shared
        let dataTask = session.dataTask(with: request, completionHandler: { (data, response, error) -> Void in
            if (error != nil) {
                completion(.failure(OAuth2PKCEAuthenticatorError.tokenRequestFailed(error!)))
                return
            } else {
                guard let data  = data else {
                    completion(.failure(OAuth2PKCEAuthenticatorError.tokenResponseNoData))
                    return
                }
                do {
                    let tokenResponse = try JSONDecoder().decode(AccessTokenResponse.self, from: data)
                    completion(.success(tokenResponse))
                } catch {
                    let reason = String(data: data, encoding: .utf8) ?? "Unknown"
                    completion(.failure(OAuth2PKCEAuthenticatorError.tokenResponseInvalidData(reason)))
                }
            }
        })
        dataTask.resume()
    }

    private func getQueryStringParameter(url: String, param: String) -> String? {
        guard let url = URLComponents(string: url) else { return nil }
        return url.queryItems?.first(where: { $0.name == param })?.value
    }
}


extension OAuth2PKCEAuthenticator: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession)
    -> ASPresentationAnchor {
        let window = UIApplication.shared.windows.first { $0.isKeyWindow }
        return window ?? ASPresentationAnchor()
    }
}

fileprivate extension URL {
    func getQueryStringParameter(_ parameter: String) -> String? {
        guard let url = URLComponents(string: self.absoluteString) else { return nil }
        return url.queryItems?.first(where: { $0.name == parameter })?.value
    }
}

fileprivate extension URLRequest {
    static func createTokenRequest(parameters: OAuth2PKCEParameters, code: String, codeVerifier: String) -> URLRequest {
        let request = NSMutableURLRequest(url: NSURL(string: "\(parameters.tokenUrl)")! as URL,
                                          cachePolicy: .useProtocolCachePolicy,
                                          timeoutInterval: 10.0)
        request.httpMethod = "POST"
        request.allHTTPHeaderFields = ["content-type": "application/x-www-form-urlencoded"]
        request.httpBody = NSMutableData(data: "grant_type=authorization_code&client_id=\(parameters.clientId)&code_verifier=\(codeVerifier)&code=\(code)&redirect_uri=\(parameters.redirectUri)".data(using: String.Encoding.utf8)!) as Data
        return request as URLRequest
    }
}

