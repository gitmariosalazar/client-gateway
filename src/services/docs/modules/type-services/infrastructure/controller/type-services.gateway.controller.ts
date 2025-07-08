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
import { CreateTypeServicesRequest } from '../../domain/schemas/dto/request/create.type-services.request';
import { UpdateTypeServicesRequest } from '../../domain/schemas/dto/request/update.type-services.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('type-services')
@ApiTags('Type Services')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class TypeServicesGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly typeSrviceClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.typeSrviceClient.subscribeToResponseOf('type-services.create');
    this.typeSrviceClient.subscribeToResponseOf('type-services.update');
    this.typeSrviceClient.subscribeToResponseOf('type-services.find-all');
    this.typeSrviceClient.subscribeToResponseOf('type-services.find-by-id');
    this.typeSrviceClient.subscribeToResponseOf('type-services.find-by-name');
    this.typeSrviceClient.subscribeToResponseOf('type-services.delete');
    await this.typeSrviceClient.connect();
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all type services ✅',
    description: 'This method retrieves all type services from the database.',
  })
  async findAll(@Req() request: Request): Promise<ApiResponse> {
    try {
      const typeServices = await sendKafkaRequest(
        this.typeSrviceClient.send('type-services.find-all', {}),
      );
      return new ApiResponse(
        'Type services retrieved successfully',
        typeServices,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idTypeService')
  @ApiOperation({
    summary: 'Method GET - Find type service by ID ✅',
    description: 'This method retrieves a type service by its ID.',
  })
  async findById(
    @Req() request: Request,
    @Param('idTypeService', ParseIntPipe) idTypeService: number,
  ): Promise<ApiResponse> {
    try {
      const typeService = await sendKafkaRequest(
        this.typeSrviceClient.send('type-services.find-by-id', {
          idTypeService: idTypeService,
        }),
      );
      return new ApiResponse(
        `Type service with ID ${idTypeService} retrieved successfully`,
        typeService,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: 'Method GET - Find type service by name ✅',
    description: 'This method retrieves a type service by its name.',
  })
  async findByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const typeService = await sendKafkaRequest(
        this.typeSrviceClient.send('type-services.find-by-name', {
          name: name,
        }),
      );
      return new ApiResponse(
        `Type service with name ${name} retrieved successfully`,
        typeService,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new type service ✅',
    description: 'This method creates a new type service in the database.',
  })
  async create(
    @Req() request: Request,
    @Body() typeServiceRequest: CreateTypeServicesRequest,
  ): Promise<ApiResponse> {
    try {
      const typeService = await sendKafkaRequest(
        this.typeSrviceClient.send('type-services.create', typeServiceRequest),
      );
      return new ApiResponse(
        'Type service created successfully',
        typeService,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idTypeService')
  @ApiOperation({
    summary: 'Method PUT - Update type service by ID ✅',
    description: 'This method updates an existing type service by its ID.',
  })
  async update(
    @Req() request: Request,
    @Param('idTypeService', ParseIntPipe) idTypeService: number,
    @Body() typeServiceRequest: UpdateTypeServicesRequest,
  ): Promise<ApiResponse> {
    try {
      const updatedTypeService = await sendKafkaRequest(
        this.typeSrviceClient.send('type-services.update', {
          idTypeService: idTypeService,
          typeServiceRequest: typeServiceRequest,
        }),
      );
      return new ApiResponse(
        `Type service with ID ${idTypeService} updated successfully`,
        updatedTypeService,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idTypeService')
  @ApiOperation({
    summary: 'Method DELETE - Delete type service by ID ✅',
    description: 'This method deletes a type service by its ID.',
  })
  async delete(
    @Req() request: Request,
    @Param('idTypeService', ParseIntPipe) idTypeService: number,
  ): Promise<ApiResponse> {
    try {
      const deleted = await sendKafkaRequest(
        this.typeSrviceClient.send('type-services.delete', {
          idTypeService: idTypeService,
        }),
      );
      return new ApiResponse(
        `Type service with ID ${idTypeService} deleted successfully`,
        deleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
