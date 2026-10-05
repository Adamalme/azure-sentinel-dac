variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "prefix" {
  description = "Short name added to every resource, e.g. a customer name"
  type        = string
  default     = "sentinel-dac"
}