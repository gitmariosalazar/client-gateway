import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import { Request } from 'express';
import { environments } from 'src/settings/environments/environments';
import { statusCode } from 'src/settings/environments/status-code';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly looger = new Logger(AuthGuard.name);
  
  constructor(private readonly jwtService: JwtService) { }
  

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    this.looger.log('Token received in the gateway ✅');

    if (!token) {
      throw new RpcException({
        statusCode: statusCode.UNAUTHORIZED,
        message: 'Authorization token is missing or malformed ❌',
      });
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: environments.jwtSecretKey,
      });
      this.looger.log('Payload verified in the gateway ✅');
      request['user'] = payload;
      request['token'] = token;
      return true;
    } catch (error) {
      
      this.looger.error(
        'Error verifying token in the gateway ❌',
        error.message,
      );

      throw new RpcException({
        statusCode: 401,
        message: 'Token is not valid or has expired ❌',
      })
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }


}
