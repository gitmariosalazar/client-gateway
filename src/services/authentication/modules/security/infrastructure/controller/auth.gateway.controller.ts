import {
  Body,
  Controller,
  Inject,
  Logger,
  OnModuleInit,
  Post,
  Req,
} from '@nestjs/common';
import { Request } from 'express';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { SignInRequest } from '../../domain/schemas/dto/request/signin.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { SignUpRequest } from '../../domain/schemas/dto/request/signup.request';
import { CreateLogsNotificationsRequest } from 'src/services/notifications/modules/notifications/domain/schemas/dto/request/create.logs-notifications.request';
import { statusCode } from 'src/settings/environments/status-code';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('auth')
@ApiTags('Authentication')
export class AuthGatewayController implements OnModuleInit {
  private readonly logger: Logger = new Logger(AuthGatewayController.name);
  constructor(
    @Inject(environments.authenticationKafkaClient)
    private readonly authClient: ClientKafka,
    @Inject(environments.notificationKafkaClient)
    private readonly notificationClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.authClient.subscribeToResponseOf('auth.signin');
    this.authClient.subscribeToResponseOf('auth.signup');
    await this.authClient.connect();
    console.log(this.authClient['responsePatterns']);
  }

  @Post('signin')
  @ApiOperation({
    summary: 'Sign in a user',
    description:
      'This endpoint allows a user to sign in using their credentials.',
  })
  async signin(
    @Req() request: Request,
    @Body() signInRequest: SignInRequest,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(
        `Received sign-in request for user: ${signInRequest.email}`,
      );
      const tokenResponse = (await sendKafkaRequest(
        this.authClient.send('auth.signin', signInRequest),
      )) as { idUser?: string; [key: string]: any };

      const clientIp =
        request.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
        request.socket.remoteAddress;

      const notification: CreateLogsNotificationsRequest = {
        log: 'User signed in successfully',
        message: `User with email ${signInRequest.email} signed in successfully.`,
        subject: 'User Sign In',
        phone: '+593994532438',
        email: signInRequest.email,
        module: 'Authentication Module',
        eventType: 'sign_in',
        userId:
          typeof tokenResponse.idUser === 'number' ? tokenResponse.idUser : 0,
        userEmail: signInRequest.email,
        ipAddress: clientIp,
        userAgent: request.headers['user-agent'],
        statusCode: statusCode.SUCCESS,
        kafkaTopic: 'auth.signin',
        correlationId: Array.isArray(request.headers['x-correlation-id'])
          ? request.headers['x-correlation-id'][0]
          : request.headers['x-correlation-id'] || '',
      };

      this.notificationClient.emit(
        'notification.send-and-create',
        notification,
      );
      this.logger.log(
        `Notification sent for user sign-in: ${signInRequest.email}`,
      );

      this.logger.log(`Sign-in successful for user: ${signInRequest.email}`);
      return new ApiResponse(
        'User signed in successfully',
        tokenResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('signup')
  @ApiOperation({
    summary: 'Sign up a new user',
    description:
      'This endpoint allows a new user to sign up and create an account.',
  })
  async signup(
    @Req() request: Request,
    @Body() signUpRequest: SignUpRequest,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(
        `Received sign-up request for user: ${signUpRequest.userEmail}`,
      );
      const clientIp =
        request.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
        request.socket.remoteAddress;
      const tokenResponse = (await sendKafkaRequest(
        this.authClient.send('auth.signup', signUpRequest),
      )) as {
        idUser?: string;
        [key: string]: any;
      };

      const notification: CreateLogsNotificationsRequest = {
        log: 'User signed up successfully',
        message: `User with email ${signUpRequest.userEmail} signed up successfully.`,
        subject: 'User Sign Up',
        phone: '+593994532438',
        email: signUpRequest.userEmail,
        module: 'Authentication Module',
        eventType: 'sign_up',
        userId:
          typeof tokenResponse.idUser === 'number' ? tokenResponse.idUser : 0,
        userEmail: signUpRequest.userEmail,
        ipAddress: clientIp,
        userAgent: request.headers['user-agent'],
        statusCode: statusCode.SUCCESS,
        kafkaTopic: 'auth.signup',
        correlationId: Array.isArray(request.headers['x-correlation-id'])
          ? request.headers['x-correlation-id'][0]
          : request.headers['x-correlation-id'] || '',
      };
      this.notificationClient.emit(
        'notification.send-and-create',
        notification,
      );
      this.logger.log(
        `Notification sent for user sign-up: ${signUpRequest.userEmail}`,
      );
      return new ApiResponse(
        'User signed up successfully',
        tokenResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
