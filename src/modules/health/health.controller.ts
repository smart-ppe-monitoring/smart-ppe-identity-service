import { Request, Response, NextFunction } from "express";
import { HealthService, healthService } from "./health.service";

export class HealthController {
  constructor(private readonly service: HealthService = healthService) {}

  getHealth = (req: Request, res: Response): void => {
    const data = this.service.getHealth();
    res.json(data);
  };

  getLiveness = (req: Request, res: Response): void => {
    const data = this.service.getLiveness();
    res.json(data);
  };

  getReadiness = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const { statusCode, data } = await this.service.getReadiness();
      res.status(statusCode).json(data);
    } catch (error) {
      next(error);
    }
  };
}

export const healthController = new HealthController();
