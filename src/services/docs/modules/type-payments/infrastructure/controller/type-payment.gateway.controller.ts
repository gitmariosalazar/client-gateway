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
import { CreateTypePaymentRequest } from '../../domain/schemas/dto/request/create.type-payment.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { UpdateTypePaymentRequest } from '../../domain/schemas/dto/request/update.type-payment.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('type-payments')
@ApiTags('Type Payments')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class TypePaymentGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly typePaymentClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.typePaymentClient.subscribeToResponseOf('typePayment.create');
    this.typePaymentClient.subscribeToResponseOf('typePayment.update');
    this.typePaymentClient.subscribeToResponseOf('typePayment.find-all');
    this.typePaymentClient.subscribeToResponseOf('typePayment.find-by-id');
    this.typePaymentClient.subscribeToResponseOf('typePayment.find-by-name');
    this.typePaymentClient.subscribeToResponseOf('typePayment.delete');
    await this.typePaymentClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new type payment ✅',
    description: 'Creates a new type payment.',
  })
  async createTypePayment(
    @Body() typePayment: CreateTypePaymentRequest,
    @Req() request: Request,
  ): Promise<ApiResponse> {
    try {
      const createdTypePayment = await sendKafkaRequest(
        this.typePaymentClient.send('typePayment.create', typePayment),
      );
      return new ApiResponse(
        'Type payment created successfully',
        createdTypePayment,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idTypePayment')
  @ApiOperation({
    summary: 'Method PUT - Update a type payment ✅',
    description: 'Updates an existing type payment by its ID.',
  })
  async updateTypePayment(
    @Body() typePayment: UpdateTypePaymentRequest,
    @Req() request: Request,
    @Param('idTypePayment', ParseIntPipe) idTypePayment: number,
  ): Promise<ApiResponse> {
    try {
      const updatedTypePayment = await sendKafkaRequest(
        this.typePaymentClient.send('typePayment.update', {
          idTypePayment,
          typePayment,
        }),
      );
      return new ApiResponse(
        'Type payment updated successfully',
        updatedTypePayment,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all type payments ✅',
    description: 'Retrieves a list of all type payments.',
  })
  async findAllTypePayments(@Req() request: Request): Promise<ApiResponse> {
    try {
      const typePayments = await sendKafkaRequest(
        this.typePaymentClient.send('typePayment.find-all', {}),
      );
      return new ApiResponse(
        'Type payments retrieved successfully',
        typePayments,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idTypePayment')
  @ApiOperation({
    summary: 'Method GET - Find type payment by ID ✅',
    description: 'Retrieves a type payment by its ID.',
  })
  async findTypePaymentById(
    @Req() request: Request,
    @Param('idTypePayment', ParseIntPipe) idTypePayment: number,
  ): Promise<ApiResponse> {
    try {
      const typePayment = await sendKafkaRequest(
        this.typePaymentClient.send('typePayment.find-by-id', {
          idTypePayment,
        }),
      );
      return new ApiResponse(
        'Type payment retrieved successfully',
        typePayment,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: 'Method GET - Find type payment by name ✅',
    description: 'Retrieves a type payment by its name.',
  })
  async findTypePaymentByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const typePayment = await sendKafkaRequest(
        this.typePaymentClient.send('typePayment.find-by-name', { name }),
      );
      return new ApiResponse(
        'Type payment retrieved successfully',
        typePayment,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idTypePayment')
  @ApiOperation({
    summary: 'Method DELETE - Delete a type payment ✅',
    description: 'Deletes a type payment by its ID.',
  })
  async deleteTypePayment(
    @Req() request: Request,
    @Param('idTypePayment', ParseIntPipe) idTypePayment: number,
  ): Promise<ApiResponse> {
    try {
      const deletedTypePayment = await sendKafkaRequest(
        this.typePaymentClient.send('typePayment.delete', { idTypePayment }),
      );
      return new ApiResponse(
        'Type payment deleted successfully',
        deletedTypePayment,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
