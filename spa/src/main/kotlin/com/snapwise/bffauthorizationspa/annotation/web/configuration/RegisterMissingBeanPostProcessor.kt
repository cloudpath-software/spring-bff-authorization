/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.snapwise.security.bff.authorization.config.annotation.web.configuration

import org.springframework.beans.BeansException
import org.springframework.beans.factory.BeanFactory
import org.springframework.beans.factory.BeanFactoryAware
import org.springframework.beans.factory.BeanFactoryUtils
import org.springframework.beans.factory.ListableBeanFactory
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.beans.factory.support.AbstractBeanDefinition
import org.springframework.beans.factory.support.BeanDefinitionRegistry
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor
import org.springframework.beans.factory.support.RootBeanDefinition
import org.springframework.context.annotation.AnnotationBeanNameGenerator
import java.util.function.Supplier

/**
 * Post processor to register one or more bean definitions on container initialization, if not already present.
 *
 * @since 0.0.1
 */
class RegisterMissingBeanPostProcessor : BeanDefinitionRegistryPostProcessor, BeanFactoryAware {
    private val beanNameGenerator: AnnotationBeanNameGenerator = AnnotationBeanNameGenerator()
    private val beanDefinitions: MutableList<AbstractBeanDefinition> = mutableListOf()
    private var beanFactory: BeanFactory? = null
    @Throws(BeansException::class)
    override fun postProcessBeanDefinitionRegistry(registry: BeanDefinitionRegistry) {
        for (beanDefinition in beanDefinitions) {
            val beanNames: Array<String> = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
                beanFactory as ListableBeanFactory, beanDefinition.beanClass, false, false
            )
            if (beanNames.isEmpty()) {
                val beanName: String = beanNameGenerator.generateBeanName(beanDefinition, registry)
                registry.registerBeanDefinition(beanName, beanDefinition)
            }
        }
    }

    @Throws(BeansException::class)
    override fun postProcessBeanFactory(beanFactory: ConfigurableListableBeanFactory) {}

    fun <T> addBeanDefinition(beanClass: Class<T>, beanSupplier: Supplier<T>) {
        beanDefinitions.add(RootBeanDefinition(beanClass, beanSupplier))
    }

    @Throws(BeansException::class)
    override fun setBeanFactory(beanFactory: BeanFactory) {
        this.beanFactory = beanFactory
    }
}