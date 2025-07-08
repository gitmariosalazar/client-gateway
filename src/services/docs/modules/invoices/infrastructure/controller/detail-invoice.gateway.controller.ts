import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  Logger,
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
import { CreateDetailInvoiceRequest } from '../../domain/schemas/dto/request/create.detail-invoice.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { UpdateDetailInvoiceRequest } from '../../domain/schemas/dto/request/update.detail-invoice.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('detail-invoice')
@ApiTags('Detail Invoice')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class DetailInvoiceGatewayController implements OnModuleInit {
  private readonly logger = new Logger(DetailInvoiceGatewayController.name);
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly kafkaClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.kafkaClient.subscribeToResponseOf('detailInvoice.create');
    this.kafkaClient.subscribeToResponseOf('detailInvoice.update');
    this.kafkaClient.subscribeToResponseOf('detailInvoice.find-all');
    this.kafkaClient.subscribeToResponseOf('detailInvoice.find-by-id');
    this.kafkaClient.subscribeToResponseOf('detailInvoice.find-by-process-id');
    this.kafkaClient.subscribeToResponseOf('detailInvoice.find-by-entity-id');
    this.kafkaClient.subscribeToResponseOf('detailInvoice.find-by-status-id');
    this.kafkaClient.subscribeToResponseOf(
      'detailInvoice.find-by-type-payment-id',
    );
    this.kafkaClient.subscribeToResponseOf('detailInvoice.find-by-document-id');
    this.kafkaClient.subscribeToResponseOf(
      'detailInvoice.find-by-invoice-number',
    );
    this.kafkaClient.subscribeToResponseOf(
      'detailInvoice.find-by-emission-date',
    );
    this.kafkaClient.subscribeToResponseOf(
      'detailInvoice.find-by-email-responsability',
    );
    this.kafkaClient.subscribeToResponseOf('detailInvoice.delete');
    await this.kafkaClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new Detail Invoice ✅',
    description:
      'This method allows you to create a new detail invoice in the system.',
  })
  async createDetailInvoice(
    @Req() request: Request,
    @Body() detailInvoice: CreateDetailInvoiceRequest,
  ): Promise<ApiResponse> {
    try {
      const detailInvoiceResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.create', detailInvoice),
      );
      if (detailInvoiceResponse) {
        this.kafkaClient.emit('detailInvoice-created', detailInvoiceResponse);
      }
      return new ApiResponse(
        'Detail Invoice created successfully',
        detailInvoiceResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idDetailInvoice')
  @ApiOperation({
    summary: 'Method PUT - Update a Detail Invoice ✅',
    description:
      'This method allows you to update an existing detail invoice in the system.',
  })
  async updateDetailInvoice(
    @Req() request: Request,
    @Param('idDetailInvoice', ParseIntPipe) idDetailInvoice: number,
    @Body() detailInvoice: UpdateDetailInvoiceRequest,
  ): Promise<ApiResponse> {
    try {
      const detailInvoiceResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.update', {
          idDetailInvoice,
          detailInvoice,
        }),
      );
      return new ApiResponse(
        'Detail Invoice updated successfully',
        detailInvoiceResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idDetailInvoice')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoice by ID ✅',
    description:
      'This method allows you to find a detail invoice by its ID in the system.',
  })
  async findByIdDetailInvoice(
    @Req() request: Request,
    @Param('idDetailInvoice', ParseIntPipe) idDetailInvoice: number,
  ): Promise<ApiResponse> {
    try {
      const detailInvoiceResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-id', { idDetailInvoice }),
      );
      return new ApiResponse(
        'Detail Invoice found successfully',
        detailInvoiceResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all Detail Invoices ✅',
    description:
      'This method allows you to find all detail invoices in the system.',
  })
  async findAllDetailInvoices(@Req() request: Request): Promise<ApiResponse> {
    try {
      this.logger.warn(
        '[Client Gateway] Sending request to find all detail invoices',
      );
      const detailInvoicesResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-all', {}),
      );
      this.logger.warn(
        '[Client Gateway] Received response for all detail invoices',
      );
      return new ApiResponse(
        'Detail Invoices found successfully',
        detailInvoicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idDetailInvoice')
  @ApiOperation({
    summary: 'Method DELETE - Delete a Detail Invoice ✅',
    description:
      'This method allows you to delete a detail invoice by its ID in the system.',
  })
  async deleteDetailInvoice(
    @Req() request: Request,
    @Param('idDetailInvoice', ParseIntPipe) idDetailInvoice: number,
  ): Promise<ApiResponse> {
    try {
      const isDeleted = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.delete', { idDetailInvoice }),
      );
      return new ApiResponse(
        'Detail Invoice deleted successfully',
        isDeleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-process-id/:idProcess')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoices by Process ID ✅',
    description:
      'This method allows you to find detail invoices by their associated process ID in the system.',
  })
  async findByProcessId(
    @Req() request: Request,
    @Param('idProcess', ParseIntPipe) idProcess: number,
  ): Promise<ApiResponse> {
    try {
      const detailInvoicesResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-process-id', {
          idProcess,
        }),
      );
      return new ApiResponse(
        'Detail Invoices by Process ID found successfully',
        detailInvoicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-entity-id/:idEntity')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoices by Entity ID ✅',
    description:
      'This method allows you to find detail invoices by their associated entity ID in the system.',
  })
  async findByEntityId(
    @Req() request: Request,
    @Param('idEntity', ParseIntPipe) idEntity: number,
  ): Promise<ApiResponse> {
    try {
      const detailInvoicesResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-entity-id', { idEntity }),
      );
      return new ApiResponse(
        'Detail Invoices by Entity ID found successfully',
        detailInvoicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-status-id/:idStatus')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoices by Status ID ✅',
    description:
      'This method allows you to find detail invoices by their associated status ID in the system.',
  })
  async findByStatusId(
    @Req() request: Request,
    @Param('idStatus', ParseIntPipe) idStatus: number,
  ): Promise<ApiResponse> {
    try {
      const detailInvoicesResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-status-id', { idStatus }),
      );
      return new ApiResponse(
        'Detail Invoices by Status ID found successfully',
        detailInvoicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-type-payment-id/:idTypePayment')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoices by Type Payment ID ✅',
    description:
      'This method allows you to find detail invoices by their associated type payment ID in the system.',
  })
  async findByTypePaymentId(
    @Req() request: Request,
    @Param('idTypePayment', ParseIntPipe) idTypePayment: number,
  ): Promise<ApiResponse> {
    try {
      const detailInvoicesResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-type-payment-id', {
          idTypePayment,
        }),
      );
      return new ApiResponse(
        'Detail Invoices by Type Payment ID found successfully',
        detailInvoicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-document-id/:idDocument')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoices by Document ID ✅',
    description:
      'This method allows you to find detail invoices by their associated document ID in the system.',
  })
  async findByDocumentId(
    @Req() request: Request,
    @Param('idDocument', ParseIntPipe) idDocument: number,
  ): Promise<ApiResponse> {
    try {
      const detailInvoicesResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-document-id', {
          idDocument,
        }),
      );
      return new ApiResponse(
        'Detail Invoices by Document ID found successfully',
        detailInvoicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-invoice-number/:invoiceNumber')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoices by Invoice Number ✅',
    description:
      'This method allows you to find detail invoices by their associated invoice number in the system.',
  })
  async findByInvoiceNumber(
    @Req() request: Request,
    @Param('invoiceNumber') invoiceNumber: string,
  ): Promise<ApiResponse> {
    try {
      const detailInvoiceResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-invoice-number', {
          invoiceNumber,
        }),
      );
      return new ApiResponse(
        'Detail Invoice by Invoice Number found successfully',
        detailInvoiceResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-emission-date/:emissionDate')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoices by Emission Date ✅',
    description:
      'This method allows you to find detail invoices by their emission date in the system.',
  })
  async findByEmissionDate(
    @Req() request: Request,
    @Param('emissionDate') emissionDate: Date,
  ): Promise<ApiResponse> {
    try {
      const detailInvoicesResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-emission-date', {
          emissionDate,
        }),
      );
      return new ApiResponse(
        'Detail Invoices by Emission Date found successfully',
        detailInvoicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-email-responsability/:emailResponsability')
  @ApiOperation({
    summary: 'Method GET - Find Detail Invoices by Email Responsibility ✅',
    description:
      'This method allows you to find detail invoices by their associated email responsibility in the system.',
  })
  async findByEmailResponsibility(
    @Req() request: Request,
    @Param('emailResponsability') emailResponsability: string,
  ): Promise<ApiResponse> {
    try {
      const detailInvoicesResponse = await sendKafkaRequest(
        this.kafkaClient.send('detailInvoice.find-by-email-responsability', {
          emailResponsability,
        }),
      );
      return new ApiResponse(
        'Detail Invoices by Email Responsibility found successfully',
        detailInvoicesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
