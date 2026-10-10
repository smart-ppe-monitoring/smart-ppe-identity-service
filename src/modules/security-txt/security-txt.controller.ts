import { Request, Response } from "express";
import { securityTxtService, SecurityTxtService } from "./security-txt.service";
import { SECURITY_TXT_PATHS } from "../../common/constants/security-txt.constant";

export class SecurityTxtController {
  private service: SecurityTxtService;

  constructor(service: SecurityTxtService = securityTxtService) {
    this.service = service;
  }

  /**
   * Trả về tệp security.txt theo định dạng RFC 9116 text/plain
   */
  getSecurityTxt = (_req: Request, res: Response): void => {
    const content = this.service.generateSecurityTxt();

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=86400"); // Cache 24 giờ
    res.status(200).send(content);
  };

  /**
   * Chuyển hướng 301 vĩnh viễn từ đường dẫn cũ /security.txt sang /.well-known/security.txt
   * theo khuyến nghị Mục 3 của RFC 9116.
   */
  redirectLegacy = (_req: Request, res: Response): void => {
    res.redirect(301, SECURITY_TXT_PATHS.WELL_KNOWN);
  };
}

export const securityTxtController = new SecurityTxtController();
