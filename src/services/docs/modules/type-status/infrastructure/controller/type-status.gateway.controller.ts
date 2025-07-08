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
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { CreateTypeStatusRequest } from '../../domain/schemas/dto/request/create.type-status.request';
import { UpdateTypeStatusRequest } from '../../domain/schemas/dto/request/update.type-status.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';
@Controller('type-status')
@ApiTags('Type Status')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class TypeStatusGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly typeStatusClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.typeStatusClient.subscribeToResponseOf('typeStatus.create');
    this.typeStatusClient.subscribeToResponseOf('typeStatus.update');
    this.typeStatusClient.subscribeToResponseOf('typeStatus.find-all');
    this.typeStatusClient.subscribeToResponseOf('typeStatus.find-by-id');
    this.typeStatusClient.subscribeToResponseOf('typeStatus.find-by-name');
    this.typeStatusClient.subscribeToResponseOf('typeStatus.delete');
    await this.typeStatusClient.connect();
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all type statuses ✅',
    description: 'Retrieves a list of all type statuses.',
  })
  async findAllTypeStatuses(@Req() request: Request): Promise<ApiResponse> {
    try {
      const typeStatuses = await sendKafkaRequest(
        this.typeStatusClient.send('typeStatus.find-all', {}),
      );
      return new ApiResponse(
        'Type statuses retrieved successfully',
        typeStatuses,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idTypeStatus')
  @ApiOperation({
    summary: 'Method GET - Find type status by ID ✅',
    description: 'Retrieves a type status by its ID.',
  })
  async findTypeStatusById(
    @Req() request: Request,
    @Param('idTypeStatus', ParseIntPipe) idTypeStatus: number,
  ): Promise<ApiResponse> {
    try {
      const typeStatus = await sendKafkaRequest(
        this.typeStatusClient.send('typeStatus.find-by-id', { idTypeStatus }),
      );
      return new ApiResponse(
        'Type status retrieved successfully',
        typeStatus,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: 'Method GET - Find type status by name ✅',
    description: 'Retrieves a type status by its name.',
  })
  async findTypeStatusByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const typeStatus = await sendKafkaRequest(
        this.typeStatusClient.send('typeStatus.find-by-name', { name }),
      );
      return new ApiResponse(
        'Type status retrieved successfully',
        typeStatus,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new type status ✅',
    description: 'Creates a new type status in the system.',
  })
  async createTypeStatus(
    @Req() request: Request,
    @Body() typeStatusRequest: CreateTypeStatusRequest,
  ): Promise<ApiResponse> {
    try {
      const createdTypeStatus = await sendKafkaRequest(
        this.typeStatusClient.send('typeStatus.create', typeStatusRequest),
      );
      return new ApiResponse(
        'Type status created successfully',
        createdTypeStatus,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idTypeStatus')
  @ApiOperation({
    summary: 'Method POST - Update type status by ID ✅',
    description: 'Updates an existing type status by its ID.',
  })
  async updateTypeStatus(
    @Req() request: Request,
    @Param('idTypeStatus', ParseIntPipe) idTypeStatus: number,
    @Body() typeStatusRequest: UpdateTypeStatusRequest,
  ): Promise<ApiResponse> {
    try {
      const updatedTypeStatus = await sendKafkaRequest(
        this.typeStatusClient.send('typeStatus.update', {
          idTypeStatus,
          typeStatusRequest,
        }),
      );
      return new ApiResponse(
        'Type status updated successfully',
        updatedTypeStatus,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idTypeStatus')
  @ApiOperation({
    summary: 'Method DELETE - Delete type status by ID ✅',
    description: 'Deletes a type status by its ID.',
  })
  async deleteTypeStatus(
    @Req() request: Request,
    @Param('idTypeStatus', ParseIntPipe) idTypeStatus: number,
  ): Promise<ApiResponse> {
    try {
      const deleted = await sendKafkaRequest(
        this.typeStatusClient.send('typeStatus.delete', {
          idTypeStatus: idTypeStatus,
        }),
      );
      return new ApiResponse(
        'Type status deleted successfully',
        deleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
