import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
    const users = await prisma.user.findMany({
        include: {
            userSchools: {
                include: {
                    school: true,
                    primaryRole: true,
                    roles: { include: { role: true } },
                },
            },
            authIdentities: true
        },
    });

    for (const user of users) {
        console.log(`User: ${user.name} (ID: ${user.id})`);
        if (user.userSchools.length > 0) {
            console.log(`  Memberships (${user.userSchools.length}):`);
            user.userSchools.forEach(us => {
                console.log(`    - School: ${us.school?.name}`);
                console.log(`      Primary Role: ${us.primaryRole?.name || 'NULL'}`);
                console.log(`      Other Roles: ${us.roles?.map(r => r.role?.name).join(', ') || 'NONE'}`);
            });
        } else {
            console.log(`  No memberships.`);
        }
    }
}

main()
    .catch(e => console.error(e))
    .finally(() => prisma.$disconnect());
