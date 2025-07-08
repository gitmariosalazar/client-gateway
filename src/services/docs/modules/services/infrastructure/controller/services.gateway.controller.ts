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
import { CreateServiceRequest } from '../../domain/schemas/dto/request/create.services.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { UpdateServiceRequest } from '../../domain/schemas/dto/request/update.services.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('services')
@ApiTags('Services')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class ServicesGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly documentsClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.documentsClient.subscribeToResponseOf('service.create');
    this.documentsClient.subscribeToResponseOf('service.update');
    this.documentsClient.subscribeToResponseOf('service.find-all');
    this.documentsClient.subscribeToResponseOf('service.find-by-id');
    this.documentsClient.subscribeToResponseOf('service.find-by-name');
    this.documentsClient.subscribeToResponseOf('service.delete');
    await this.documentsClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: `Method POST - Create a new service ✅`,
    description: 'Creates a new service with the provided details.',
  })
  async createService(
    @Req() request: Request,
    @Body() service: CreateServiceRequest,
  ): Promise<ApiResponse> {
    try {
      const serviceResponse = await sendKafkaRequest(
        this.documentsClient.send('service.create', service),
      );
      return new ApiResponse(
        'Service created successfully',
        serviceResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idService')
  @ApiOperation({
    summary: `Method PUT - Update an existing service ✅`,
    description: 'Updates an existing service with the provided details.',
  })
  async updateService(
    @Req() request: Request,
    @Body() service: UpdateServiceRequest,
    @Param('idService', ParseIntPipe) idService: number,
  ): Promise<ApiResponse> {
    try {
      const serviceResponse = await sendKafkaRequest(
        this.documentsClient.send('service.update', { idService, service }),
      );
      return new ApiResponse(
        'Service updated successfully',
        serviceResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: `Method GET - Retrieve all services ✅`,
    description: 'Retrieves a list of all services.',
  })
  async findAllServices(@Req() request: Request): Promise<ApiResponse> {
    try {
      const servicesResponse = await sendKafkaRequest(
        this.documentsClient.send('service.find-all', {}),
      );
      return new ApiResponse(
        'Services retrieved successfully',
        servicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idService')
  @ApiOperation({
    summary: `Method GET - Retrieve a service by ID ✅`,
    description: 'Retrieves a service by its ID.',
  })
  async findServiceById(
    @Req() request: Request,
    @Param('idService', ParseIntPipe) idService: number,
  ): Promise<ApiResponse> {
    try {
      const serviceResponse = await sendKafkaRequest(
        this.documentsClient.send('service.find-by-id', { idService }),
      );
      return new ApiResponse(
        'Service retrieved successfully',
        serviceResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: `Method GET - Retrieve a service by name ✅`,
    description: 'Retrieves a service by its name.',
  })
  async findServiceByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const serviceResponse = await sendKafkaRequest(
        this.documentsClient.send('service.find-by-name', { name }),
      );
      return new ApiResponse(
        'Service retrieved successfully',
        serviceResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idService')
  @ApiOperation({
    summary: `Method DELETE - Delete a service ✅`,
    description: 'Deletes a service by its ID.',
  })
  async deleteService(
    @Req() request: Request,
    @Param('idService', ParseIntPipe) idService: number,
  ): Promise<ApiResponse> {
    try {
      const deleteResponse = await sendKafkaRequest(
        this.documentsClient.send('service.delete', { idService }),
      );
      return new ApiResponse(
        'Service deleted successfully',
        deleteResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
