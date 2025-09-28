FROM php:8.4-apache

RUN apt-get update \
	&& apt-get install libyaml-dev -y \
	&& pecl install yaml \
	&& echo "extension=yaml.so" > /usr/local/etc/php/conf.d/ext-yaml.ini \
	&& docker-php-ext-enable yaml

RUN a2enmod rewrite
RUN rm -rf /var/www

COPY www/ /var/www

