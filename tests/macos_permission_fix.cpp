#include <mach-o/loader.h>

#include <fstream>
#include <iostream>
#include <vector>

struct section_t
{
    segment_command_64 cmd;
    std::vector<section_64> sections;
};

int main(int argc, char* argv[])
{
    std::fstream f(argv[1], std::ios::in | std::ios::out | std::ios::binary);

    uint32_t magic;

    f.read((char*)&magic, 4);
    if( magic == MH_MAGIC_64 )
    {
        f.seekg(0, std::ios::beg);
        mach_header_64 hdr;
        f.read((char*)&hdr, sizeof(hdr));

        std::vector<section_t> section_headers;

        section_headers.resize(hdr.ncmds);

        std::cout << "Load command count: " << hdr.ncmds << std::endl;
        for (int i = 0; i < hdr.ncmds; ++i)
        {
            int pos = (int)f.tellg();
            f.read((char*)&section_headers[i].cmd, sizeof(segment_command_64));

            if ( section_headers[i].cmd.cmd == LC_SEGMENT_64 )
            {
                std::cout << "Load Command: " << section_headers[i].cmd.segname << std::endl;
                if (strncmp(section_headers[i].cmd.segname, "__TEXT", 6) == 0)
                {
                    std::cout << "__TEXT Load command found, making the text section more permissive..." << std::endl;
                    int p = f.tellg();
                    f.seekp(p-(int)sizeof(segment_command_64));
                    section_headers[i].cmd.maxprot = 7;
                    f.write((char*)&section_headers[i].cmd, sizeof(segment_command_64));
                    f.seekg(p);
                }

                section_headers[i].sections.resize(section_headers[i].cmd.nsects);
                for (int j = 0; j < section_headers[i].cmd.nsects; ++j)
                {
                    f.read((char*)&section_headers[i].sections[j], sizeof(section_64));

                    std::cout << "  Section: " << section_headers[i].sections[j].sectname << std::endl;
                }
            }
            else
            {
                std::cout << "Unknown segment command type: " << section_headers[i].cmd.cmd << std::endl;
            }
            f.seekg(pos + (int)section_headers[i].cmd.cmdsize);
        }
    }

    return 0;
}