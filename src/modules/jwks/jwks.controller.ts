import { Request, Response, NextFunction } from "express";
import { JwksService, jwksService } from "./jwks.service";
import { JWKS_CONSTANTS } from "../../common/constants/jwt.constant";

export class JwksController {
  private readonly service: JwksService;

  constructor(service?: JwksService) {
    this.service = service || jwksService;
  }

  /**
   * Trả về JWKS (JSON Web Key Set) RFC 7517
   */
  public getJwks = (req: Request, res: Response, next: NextFunction): void => {
    try {
      const jwks = this.service.getJwks();

      res.setHeader("Content-Type", JWKS_CONSTANTS.CONTENT_TYPE);
      res.setHeader("Cache-Control", JWKS_CONSTANTS.HTTP_CACHE_CONTROL);
      res.status(200).json(jwks);
    } catch (error) {
      next(error);
    }
  };
}

export const jwksController = new JwksController();
