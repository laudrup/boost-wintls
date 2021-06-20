#pragma once
#include <map>
#include <string>

using TemplateDefinitions = std::map<std::string, std::string>;

std::string ApplyTemplate(const std::string& template_file, const TemplateDefinitions& definitions);
