import {
  jwtKeyService,
  JwtKeyService,
  JwksResponse,
} from "../../common/services/jwt-key.service";

export class JwksService {
  private readonly keyService: JwtKeyService;

  constructor(keyService?: JwtKeyService) {
    this.keyService = keyService || jwtKeyService;
  }

  /**
   * Lấy danh sách JWKS (RFC 7517) chứa các Public Keys hợp lệ
   */
  public getJwks(): JwksResponse {
    return this.keyService.getJwks();
  }
}

export const jwksService = new JwksService();
