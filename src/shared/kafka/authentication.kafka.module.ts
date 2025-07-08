import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';

@Module({
  imports: [
    ClientsModule.register([
      {
        name: environments.authenticationKafkaClient!,
        transport: Transport.KAFKA,
        options: {
          client: {
            clientId: environments.authenticationKafkaClientId,
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.authenticationKafkaGroupId!,
          },
        },
      },
    ]),
  ],
  exports: [ClientsModule],
})
export class AuthenticationKafkaModule {}
