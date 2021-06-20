#include "template.h"
#include <regex>
/* This is a brute force way of doing this (but hey this is example code */
std::string ApplyTemplate(const std::string& template_file, const TemplateDefinitions& definitions)
{
	using namespace std::string_literals;
	std::string partial{ template_file };
	for (const auto replacement : definitions)
	{
		std::regex find_variable_regex("\\$\\("s + replacement.first + "\\)");   // matches just this variable
		const auto new_partial = std::regex_replace(partial, find_variable_regex, replacement.second); // replace variable->value
		partial = new_partial;
	}
	return partial;
}
