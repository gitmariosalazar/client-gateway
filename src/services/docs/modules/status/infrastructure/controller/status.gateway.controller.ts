import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  Inject,
  Req,
  OnModuleInit,
  UseGuards,
} from '@nestjs/common';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { CreateStatusRequest } from '../../domain/schemas/dto/request/create.status.request';
import { UpdateStatusRequest } from '../../domain/schemas/dto/request/update.status.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('status')
@ApiTags('Status')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class StatusGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly statusClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.statusClient.subscribeToResponseOf('status.create');
    this.statusClient.subscribeToResponseOf('status.update');
    this.statusClient.subscribeToResponseOf('status.find-all');
    this.statusClient.subscribeToResponseOf('status.find-by-id');
    this.statusClient.subscribeToResponseOf('status.find-by-name');
    this.statusClient.subscribeToResponseOf('status.delete');
    await this.statusClient.connect();
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all status ✅',
    description: 'Retrieves a list of all status.',
  })
  async findAllStatus(@Req() request: Request): Promise<ApiResponse> {
    try {
      const statuses = await sendKafkaRequest(
        this.statusClient.send('status.find-all', {}),
      );
      return new ApiResponse(
        'Status retrieved successfully.',
        statuses,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idStatus')
  @ApiOperation({
    summary: 'Method GET - Find status by ID ✅',
    description: 'Retrieves a status by its ID.',
  })
  async findStatusById(
    @Req() request: Request,
    @Param('idStatus', ParseIntPipe) idStatus: number,
  ): Promise<ApiResponse> {
    try {
      const status = await sendKafkaRequest(
        this.statusClient.send('status.find-by-id', { idStatus }),
      );
      return new ApiResponse(
        'Status retrieved successfully.',
        status,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: 'Method GET - Find status by name ✅',
    description: 'Retrieves a status by its name.',
  })
  async findStatusByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const status = await sendKafkaRequest(
        this.statusClient.send('status.find-by-name', { name }),
      );
      return new ApiResponse(
        'Status retrieved successfully.',
        status,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new status ✅',
    description: 'Creates a new status.',
  })
  async createStatus(
    @Req() request: Request,
    @Body() status: CreateStatusRequest,
  ): Promise<ApiResponse> {
    try {
      const createdStatus = await sendKafkaRequest(
        this.statusClient.send('status.create', status),
      );
      return new ApiResponse(
        'Status created successfully.',
        createdStatus,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idStatus')
  @ApiOperation({
    summary: 'Method PUT - Update a status ✅',
    description: 'Updates an existing status by its ID.',
  })
  async updateStatus(
    @Req() request: Request,
    @Param('idStatus', ParseIntPipe) idStatus: number,
    @Body() status: UpdateStatusRequest,
  ): Promise<ApiResponse> {
    try {
      const updatedStatus = await sendKafkaRequest(
        this.statusClient.send('status.update', { idStatus, status }),
      );
      return new ApiResponse(
        'Status updated successfully.',
        updatedStatus,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idStatus')
  @ApiOperation({
    summary: 'Method DELETE - Delete a status ✅',
    description: 'Deletes a status by its ID.',
  })
  async deleteStatus(
    @Req() request: Request,
    @Param('idStatus', ParseIntPipe) idStatus: number,
  ): Promise<ApiResponse> {
    try {
      const deletedStatus = await sendKafkaRequest(
        this.statusClient.send('status.delete', { idStatus }),
      );
      return new ApiResponse(
        'Status deleted successfully.',
        deletedStatus,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
