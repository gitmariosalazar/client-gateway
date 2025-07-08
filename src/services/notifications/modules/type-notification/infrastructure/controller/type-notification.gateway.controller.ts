import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  OnModuleInit,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { CreateTypeNotificationRequest } from '../../domain/schemas/dto/request/create.type-notification.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { UpdateTypeNotificationRequest } from '../../domain/schemas/dto/request/update.type-notification.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('type-notification')
@ApiTags('Type Notification')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class TypeNotificationGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.notificationKafkaClient)
    private readonly typeNotificationClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.typeNotificationClient.subscribeToResponseOf(
      'typeNotification.create',
    );
    this.typeNotificationClient.subscribeToResponseOf(
      'typeNotification.update',
    );
    this.typeNotificationClient.subscribeToResponseOf(
      'typeNotification.findAll',
    );
    this.typeNotificationClient.subscribeToResponseOf(
      'typeNotification.find-by-id',
    );
    this.typeNotificationClient.subscribeToResponseOf(
      'typeNotification.find-by-name',
    );
    this.typeNotificationClient.subscribeToResponseOf(
      'typeNotification.delete',
    );
    await this.typeNotificationClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new type of notification ✅',
    description:
      'Creates a new type of notification with the provided details.',
  })
  async createTypeNotification(
    @Req() request: Request,
    @Body() typeNotification: CreateTypeNotificationRequest,
  ): Promise<ApiResponse> {
    try {
      const typeNotificationResponse = await sendKafkaRequest(
        this.typeNotificationClient.send(
          'typeNotification.create',
          typeNotification,
        ),
      );
      return new ApiResponse(
        'Type notification created successfully',
        typeNotificationResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idTypeNotification')
  @ApiOperation({
    summary: 'Method PUT - Update an existing type of notification ✅',
    description:
      'Updates an existing type of notification with the provided details.',
  })
  async updateTypeNotification(
    @Req() request: Request,
    @Param('idTypeNotification', ParseIntPipe) idTypeNotification: number,
    @Body()
    typeNotification: UpdateTypeNotificationRequest,
  ): Promise<ApiResponse> {
    try {
      const typeNotificationResponse = await sendKafkaRequest(
        this.typeNotificationClient.send('typeNotification.update', {
          idTypeNotification,
          typeNotification,
        }),
      );
      return new ApiResponse(
        'Type notification updated successfully',
        typeNotificationResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Retrieve all types of notifications ✅',
    description: 'Fetches all types of notifications from the database.',
  })
  async findAllTypeNotifications(
    @Req() request: Request,
  ): Promise<ApiResponse> {
    try {
      const typeNotificationsResponse = await sendKafkaRequest(
        this.typeNotificationClient.send('typeNotification.findAll', {}),
      );
      return new ApiResponse(
        'Type notifications retrieved successfully',
        typeNotificationsResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idTypeNotification')
  @ApiOperation({
    summary: 'Method GET - Retrieve a type of notification by ID ✅',
    description: 'Fetches a type of notification by its ID from the database.',
  })
  async findTypeNotificationById(
    @Req() request: Request,
    @Param('idTypeNotification', ParseIntPipe) idTypeNotification: number,
  ): Promise<ApiResponse> {
    try {
      const typeNotificationResponse = await sendKafkaRequest(
        this.typeNotificationClient.send('typeNotification.find-by-id', {
          idTypeNotification,
        }),
      );
      return new ApiResponse(
        'Type notification retrieved successfully',
        typeNotificationResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: 'Method GET - Retrieve a type of notification by name ✅',
    description:
      'Fetches a type of notification by its name from the database.',
  })
  async findTypeNotificationByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const typeNotificationResponse = await sendKafkaRequest(
        this.typeNotificationClient.send('typeNotification.find-by-name', {
          name,
        }),
      );
      return new ApiResponse(
        'Type notification retrieved successfully',
        typeNotificationResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idTypeNotification')
  @ApiOperation({
    summary: 'Method DELETE - Delete a type of notification by ID ✅',
    description: 'Deletes a type of notification by its ID from the database.',
  })
  async deleteTypeNotification(
    @Req() request: Request,
    @Param('idTypeNotification', ParseIntPipe) idTypeNotification: number,
  ): Promise<ApiResponse> {
    try {
      const deleted = await sendKafkaRequest(
        this.typeNotificationClient.send('typeNotification.delete', {
          idTypeNotification,
        }),
      );
      return new ApiResponse(
        'Type notification deleted successfully',
        deleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
